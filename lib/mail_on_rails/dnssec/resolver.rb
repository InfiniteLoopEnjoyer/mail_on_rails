# frozen_string_literal: true

module MailOnRails
  module Dnssec
    # A validating stub forwarder: queries an upstream recursive with CD
    # set (so nothing is filtered on our behalf) and validates everything
    # in process - RRSIG chains walked zone by zone up to the root trust
    # anchor, denials proven with NSEC/NSEC3 - so upstream needs no trust
    # at all. Smtp::SenderAuth::Dns rides this for the outbound DANE
    # lookups (it formerly trusted a loopback resolver's AD bit instead).
    #
    # resolve() returns an Answer whose status carries the RFC 4035
    # section 4.3 verdict:
    #
    #   :secure   - every link from the root anchor to the answer (or to
    #               the denial proof) verified.
    #   :insecure - the name provably sits outside DNSSEC (unsigned
    #               delegation, Opt-Out span, unsupported algorithm).
    #               Records are returned and usable for routing, but for
    #               DANE (RFC 7672) this means "no DANE", never
    #               "securely absent".
    #   :bogus    - validation failed: missing or wrong signatures, a
    #               denial that proves nothing, a resource-cap trip. A
    #               DANE caller must treat this as delivery-deferring
    #               (the moral equivalent of the old SERVFAIL), not as
    #               absence.
    #
    # Transport failures raise Transport::TempError; :bogus is reserved
    # for responses that arrived and failed validation.
    #
    # Resource caps (KeyTrap lessons, CVE-2023-50387): queries, signature
    # verifications, and denial-record counts are budgeted per resolve()
    # and trip to :bogus - a pure-Ruby validator must never let a
    # response buy unbounded CPU.
    class Resolver
      Answer = Struct.new(:status, :records, :proof, :reason, keyword_init: true)

      MAX_QUERIES = 32          # chain walks are ~2 per zone cut; 32 is generous
      MAX_CRYPTO = 64           # signature verifications per resolve
      MAX_SIGS_PER_RRSET = 4    # (sig, key) pairs attempted per RRset
      MAX_KEYS_PER_SIG = 3
      MAX_DNSKEYS = 16          # larger DNSKEY RRsets are hostile, not real
      MAX_DENIAL_RECORDS = 24
      MAX_CNAME_DEPTH = 8
      MAX_CHAIN_DEPTH = 16
      INSECURE_CACHE_TTL = 300
      SECURE_CACHE_TTL_CAP = 3600

      # DS records naming algorithms we cannot verify make the zone
      # insecure, not bogus (RFC 4035 section 5.2) - so the usable set
      # must reflect what verify_rrset can actually do.
      SUPPORTED_ALGORITHMS = [ 3, 5, 6, 7, 8, 10, 13, 14, 15, 16 ].freeze
      SUPPORTED_DS_DIGESTS = [ 1, 2, 4 ].freeze

      class Budget
        class Exceeded < StandardError; end

        def initialize(queries: MAX_QUERIES, crypto: MAX_CRYPTO)
          @queries = queries
          @crypto = crypto
        end

        def query!
          @queries -= 1
          raise Exceeded, "query budget exhausted" if @queries.negative?
        end

        def crypto!
          @crypto -= 1
          raise Exceeded, "crypto budget exhausted" if @crypto.negative?
        end
      end

      Ctx = Struct.new(:budget, :verifier, :stack)

      # +transport+ needs only query(name, type) => Dnsruby::Message.
      # +now+ is the verification clock (tests pin it to replay captured
      # responses). +trust_anchors+ maps canonical zone names to DS
      # records; the default is the IANA root.
      def initialize(nameservers: nil, transport: nil, trust_anchors: TrustAnchors.default,
                     now: -> { Time.now }, cache_ttl_cap: SECURE_CACHE_TTL_CAP, budget: {},
                     fallback_nameservers: Transport::FALLBACK_NAMESERVERS)
        @budget_opts = budget
        @transport = transport || Transport.new(nameservers: nameservers,
                                                fallback_nameservers: fallback_nameservers)
        @anchors = {}
        @anchor_names = []
        trust_anchors.each do |zone, ds_records|
          name = to_name(zone)
          @anchors[name.canonical] = ds_records
          @anchor_names << name
        end
        @now = now
        @cache_ttl_cap = cache_ttl_cap
        @zone_cache = {} # canonical zone => {status:, keys:, expires:}
        @lock = Mutex.new
      end

      def resolve(qname, qtype)
        verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
        verifier.verification_time = @now.call
        ctx = Ctx.new(Budget.new(**@budget_opts), verifier, [])
        chase(to_name(qname), Dnsruby::Types.new(qtype), ctx, 0)
      rescue Budget::Exceeded => e
        Answer.new(status: :bogus, records: [], reason: "resource budget exceeded (#{e.message}) - hostile response shape?")
      end

      private

      def chase(qname, qtype, ctx, cname_depth)
        msg = query(qname, qtype, ctx)

        rrset = msg.answer.rrset(qname, qtype)
        return validate_positive(msg, rrset, qname, ctx) if rrset.length > 0

        cname = msg.answer.rrset(qname, Dnsruby::Types.CNAME)
        if cname.length > 0 && qtype != Dnsruby::Types.CNAME
          return bogus("CNAME chain exceeds #{MAX_CNAME_DEPTH} links") if cname_depth >= MAX_CNAME_DEPTH

          link = validate_positive(msg, cname, qname, ctx)
          return link if link.status == :bogus

          rest = chase(to_name(cname.rrs[0].cname), qtype, ctx, cname_depth + 1)
          status = worst_status(link.status, rest.status)
          return Answer.new(status: status, records: rest.records, proof: rest.proof,
                            reason: status == rest.status ? rest.reason : link.reason)
        end

        validate_negative(msg, qname, qtype, ctx)
      end

      def query(name, type, ctx)
        ctx.budget.query!
        msg = @transport.query(name.to_s(true), type)
        rcode = msg.rcode
        unless rcode == Dnsruby::RCode.NOERROR || rcode == Dnsruby::RCode.NXDOMAIN
          raise Transport::TempError, "upstream returned #{rcode} for #{name} #{type}"
        end
        msg
      end

      # ----- positive answers ------------------------------------------

      def validate_positive(msg, rrset, qname, ctx)
        sigs = rrset.sigs
        if sigs.empty?
          status = unsigned_status(qname, ctx)
          return bogus("unsigned answer for #{qname} inside a signed zone") unless status == :insecure

          return Answer.new(status: :insecure, records: rrset.rrs,
                            reason: "answer outside the chain of trust")
        end

        signer = to_name(sigs[0].signers_name)
        unless ancestor_or_equal?(signer, qname)
          return bogus("RRSIG signer #{signer} is out of bailiwick for #{qname}")
        end

        zone = zone_keys(signer, ctx)
        case zone[:status]
        when :insecure
          Answer.new(status: :insecure, records: rrset.rrs,
                     reason: "zone #{signer} is outside the chain of trust")
        when :bogus
          bogus(zone[:reason] || "chain of trust to #{signer} failed")
        else
          sig = verify_with_keys(rrset, zone[:keys], signer, ctx)
          return bogus("signature on #{qname}/#{rrset.type} failed to verify") unless sig

          if sig.labels < qname.labels.length
            wildcard_status = wildcard_proof_status(msg, qname, sig.labels, zone[:keys], signer, ctx)
            return bogus("wildcard expansion for #{qname} is unproven") unless wildcard_status

            return Answer.new(status: wildcard_status, records: rrset.rrs, proof: :wildcard_answer)
          end
          Answer.new(status: :secure, records: rrset.rrs)
        end
      end

      def wildcard_proof_status(msg, qname, rrsig_labels, keys, zone, ctx)
        nsec3s, nsecs = verified_denial_records(msg, keys, zone, ctx)
        result = Dnsruby::Nsec3Proof.wildcard_answer(qname, rrsig_labels, nsec3s) ||
                 Dnsruby::NsecProof.wildcard_answer(qname, rrsig_labels, nsecs)
        result&.status
      end

      # ----- negative answers ------------------------------------------

      def validate_negative(msg, qname, qtype, ctx)
        soa_rrset = msg.authority.rrsets("SOA")[0]
        if soa_rrset.nil? || soa_rrset.rrs.empty?
          status = unsigned_status(qname, ctx)
          return bogus("negative response without SOA for #{qname} in a signed zone") unless status == :insecure

          return Answer.new(status: :insecure, records: [], reason: "denial outside the chain of trust")
        end

        zone_name = to_name(soa_rrset.name)
        return bogus("SOA owner #{zone_name} out of bailiwick for #{qname}") unless ancestor_or_equal?(zone_name, qname)

        zone = zone_keys(zone_name, ctx)
        case zone[:status]
        when :insecure
          return Answer.new(status: :insecure, records: [], reason: "zone #{zone_name} is outside the chain of trust")
        when :bogus
          return bogus(zone[:reason] || "chain of trust to #{zone_name} failed")
        end

        return bogus("SOA of #{zone_name} failed to verify") unless verify_with_keys(soa_rrset, zone[:keys], zone_name, ctx)

        nsec3s, nsecs = verified_denial_records(msg, zone[:keys], zone_name, ctx)
        result =
          if msg.rcode == Dnsruby::RCode.NXDOMAIN
            Dnsruby::Nsec3Proof.name_error(qname, nsec3s) ||
              Dnsruby::NsecProof.name_error(qname, nsecs)
          else
            Dnsruby::Nsec3Proof.no_data(qname, qtype, nsec3s) ||
              Dnsruby::Nsec3Proof.wildcard_no_data(qname, qtype, nsec3s) ||
              Dnsruby::NsecProof.no_data(qname, qtype, nsecs)
          end
        return bogus("denial of #{qname}/#{qtype} is unproven") unless result

        Answer.new(status: result.status, records: [], proof: result.proof)
      end

      # NSEC/NSEC3 RRsets are only proof material once their own
      # signatures verify under the zone's keys - an attacker can inject
      # authority records freely, so unverified ones are dropped, and
      # the total is capped.
      def verified_denial_records(msg, keys, zone, ctx)
        nsec3s = []
        nsecs = []
        total = 0
        (msg.authority.rrsets("NSEC3") + msg.authority.rrsets("NSEC")).each do |rrset|
          next if rrset.rrs.empty?
          next if (total += rrset.rrs.length) > MAX_DENIAL_RECORDS
          next unless verify_with_keys(rrset, keys, zone, ctx)

          (rrset.type == Dnsruby::Types.NSEC3 ? nsec3s : nsecs).concat(rrset.rrs)
        end
        [ Dnsruby::Nsec3Proof.usable(nsec3s), nsecs ]
      end

      # ----- chain of trust --------------------------------------------

      # Validated DNSKEYs for +zone+: {status: :secure, keys:} once the
      # zone's DNSKEY RRset verifies against a DS RRset whose own chain
      # reaches a trust anchor; {status: :insecure} when the chain
      # provably breaks at an unsigned delegation on the way.
      def zone_keys(zone, ctx)
        key = zone.canonical
        if (cached = cache_get(key))
          return cached
        end
        return { status: :bogus, reason: "circular chain of trust at #{zone}" } if ctx.stack.include?(key)
        return { status: :bogus, reason: "chain of trust deeper than #{MAX_CHAIN_DEPTH}" } if ctx.stack.length >= MAX_CHAIN_DEPTH

        ctx.stack.push(key)
        result = compute_zone_keys(zone, ctx)
        ctx.stack.pop
        cache_put(key, result)
        result
      end

      def compute_zone_keys(zone, ctx)
        ds = ds_for(zone, ctx)
        case ds[:status]
        when :insecure then return { status: :insecure }
        when :bogus then return { status: :bogus, reason: ds[:reason] }
        when :continue, :nxdomain
          # The parent proved there is no delegation here at all - yet
          # something named this zone as its signer.
          return { status: :bogus, reason: "#{zone} is provably not a zone cut" }
        end

        msg = query(zone, Dnsruby::Types.DNSKEY, ctx)
        krrset = msg.answer.rrset(zone, Dnsruby::Types.DNSKEY)
        return { status: :bogus, reason: "no DNSKEY RRset for #{zone}" } if krrset.length.zero?
        return { status: :bogus, reason: "oversized DNSKEY RRset for #{zone}" } if krrset.rrs.length > MAX_DNSKEYS

        ksks = krrset.rrs.select do |k|
          ds[:ds].any? do |d|
            ctx.budget.crypto!
            d.check_key(k)
          end
        end
        return { status: :bogus, reason: "no DNSKEY of #{zone} matches its DS RRset" } if ksks.empty?
        return { status: :bogus, reason: "DNSKEY RRset of #{zone} failed to verify" } unless verify_with_keys(krrset, ksks, zone, ctx)

        ttl = [ @cache_ttl_cap, krrset.ttl ].min
        { status: :secure, keys: krrset.rrs, ttl: ttl }
      end

      # The DS story for +zone+, asked of its parent:
      #   :secure   - verified DS RRset (or a configured trust anchor)
      #   :insecure - proven unsigned delegation or Opt-Out span
      #   :continue - proven "exists, no DS, not a delegation" (only
      #               meaningful to the top-down walk)
      #   :nxdomain - proven nonexistent
      #   :bogus    - proves nothing
      def ds_for(zone, ctx)
        if (anchor = @anchors[zone.canonical])
          usable = usable_ds(anchor)
          return usable.empty? ? { status: :insecure } : { status: :secure, ds: usable }
        end
        return { status: :bogus, reason: "no trust anchor above #{zone}" } if zone.labels.empty?

        msg = query(zone, Dnsruby::Types.DS, ctx)
        ds_rrset = msg.answer.rrset(zone, Dnsruby::Types.DS)
        return validate_ds_denial(msg, zone, ctx) if ds_rrset.length.zero?

        sigs = ds_rrset.sigs
        return { status: :bogus, reason: "unsigned DS RRset for #{zone}" } if sigs.empty?

        parent = to_name(sigs[0].signers_name)
        unless strict_ancestor?(parent, zone)
          return { status: :bogus, reason: "DS for #{zone} signed by non-ancestor #{parent}" }
        end

        pkeys = zone_keys(parent, ctx)
        case pkeys[:status]
        when :insecure then return { status: :insecure }
        when :bogus then return { status: :bogus, reason: pkeys[:reason] }
        end
        return { status: :bogus, reason: "DS RRset for #{zone} failed to verify" } unless verify_with_keys(ds_rrset, pkeys[:keys], parent, ctx)

        usable = usable_ds(ds_rrset.rrs)
        # All-unsupported-algorithms is a provably unverifiable zone:
        # insecure, not bogus (RFC 4035 section 5.2).
        usable.empty? ? { status: :insecure } : { status: :secure, ds: usable }
      end

      # A negative DS answer classified through its (verified) denial
      # records. The parent zone comes from the SOA; its keys verify the
      # NSEC(3)s; the proofs then say which kind of absence this is.
      def validate_ds_denial(msg, zone, ctx)
        soa_rrset = msg.authority.rrsets("SOA")[0]
        return { status: :bogus, reason: "DS denial for #{zone} carries no SOA" } if soa_rrset.nil? || soa_rrset.rrs.empty?

        parent = to_name(soa_rrset.name)
        unless ancestor_or_equal?(parent, zone) && parent.canonical != zone.canonical
          return { status: :bogus, reason: "DS denial for #{zone} from non-parent #{parent}" }
        end

        pkeys = zone_keys(parent, ctx)
        case pkeys[:status]
        when :insecure then return { status: :insecure }
        when :bogus then return { status: :bogus, reason: pkeys[:reason] }
        end
        return { status: :bogus, reason: "SOA in DS denial for #{zone} failed to verify" } unless verify_with_keys(soa_rrset, pkeys[:keys], parent, ctx)

        nsec3s, nsecs = verified_denial_records(msg, pkeys[:keys], parent, ctx)

        if msg.rcode == Dnsruby::RCode.NXDOMAIN
          result = Dnsruby::Nsec3Proof.name_error(zone, nsec3s) ||
                   Dnsruby::NsecProof.name_error(zone, nsecs)
          return { status: :bogus, reason: "DS NXDOMAIN for #{zone} is unproven" } unless result

          return { status: result.status == :secure ? :nxdomain : :insecure }
        end

        ds_nodata_status(zone, nsec3s, nsecs)
      end

      # NODATA for DS, distinguished by the matching record's bitmap: NS
      # present means an unsigned delegation (:insecure); absent means
      # no zone cut here (:continue); an Opt-Out span could hide either
      # (:insecure, conservatively).
      def ds_nodata_status(zone, nsec3s, nsecs)
        if (m = nsec3s.find { |rr| rr.matches?(zone) })
          return { status: :bogus, reason: "NSEC3 for #{zone} claims DS exists" } if m.types.include?("DS")

          return { status: m.types.include?("NS") ? :insecure : :continue }
        end
        if (ce = Dnsruby::Nsec3Proof.closest_encloser_proof(zone, nsec3s))
          return { status: :insecure } if ce[:covering].opt_out?
        end

        if (m = nsecs.find { |rr| Dnsruby::NsecProof.matches?(rr, zone) })
          return { status: :bogus, reason: "NSEC for #{zone} claims DS exists" } if m.types.include?("DS")

          return { status: m.types.include?("NS") ? :insecure : :continue }
        end
        # A wildcard-synthesized DS NODATA can't be a delegation.
        if Dnsruby::Nsec3Proof.wildcard_no_data(zone, Dnsruby::Types.DS, nsec3s) ||
           Dnsruby::NsecProof.no_data(zone, Dnsruby::Types.DS, nsecs)
          return { status: :continue }
        end

        { status: :bogus, reason: "DS NODATA for #{zone} is unproven" }
      end

      # Classifies an unsigned (or proof-less) answer by walking the
      # label boundaries from the nearest trust anchor down to +qname+,
      # looking for the provable break in the chain. Only an :insecure
      # verdict legitimizes unsigned data.
      def unsigned_status(qname, ctx)
        apex = deepest_anchor_ancestor(qname)
        return :bogus unless apex

        remaining = qname.labels.length - apex.labels.length
        (1..remaining).each do |depth|
          cut = Dnsruby::Name.new(qname.labels.last(apex.labels.length + depth), true)
          ds = ds_for(cut, ctx)
          case ds[:status]
          when :insecure then return :insecure
          when :nxdomain, :bogus then return :bogus
          end
          # :secure and :continue both mean "still inside signed space" -
          # keep descending.
        end
        :bogus # every cut on the path is signed; unsigned data is a lie
      end

      def deepest_anchor_ancestor(qname)
        @anchor_names.select { |name| ancestor_or_equal?(name, qname) }
                     .max_by { |name| name.labels.length }
      end

      # ----- signature plumbing ----------------------------------------

      # Verifies +rrset+ with bounded (signature, key) attempts, all
      # constrained to +expected_signer+. Returns the RRSIG that
      # verified (its Labels field feeds wildcard detection), or nil.
      def verify_with_keys(rrset, keys, expected_signer, ctx)
        expected = expected_signer.canonical
        rrset.sigs.first(MAX_SIGS_PER_RRSET).each do |sig|
          next unless to_name(sig.signers_name).canonical == expected
          next if sig.labels > rrset.name.labels.length # RFC 4035 5.3.1

          candidates = keys.select { |k| k.key_tag == sig.key_tag && k.algorithm == sig.algorithm }
          candidates.first(MAX_KEYS_PER_SIG).each do |key|
            ctx.budget.crypto!
            begin
              return sig if ctx.verifier.verify_rrset(verifiable_rrset(rrset, sig), [ key ])
            rescue Dnsruby::VerifyError
              next
            end
          end
        end
        nil
      end

      # The RRset as the signer signed it. For a wildcard-expanded
      # answer (RFC 4035 section 5.3.2, Labels < owner labels) the
      # signature was made over the original "*.<parent>" owner - a
      # reconstruction dnsruby's own sig_data skips (its literal
      # "@TODO@ worry about wildcards") - so owner names are rewritten
      # before verification.
      def verifiable_rrset(rrset, sig)
        owner =
          if sig.labels < rrset.name.labels.length
            Dnsruby::Name.create("*." + Dnsruby::Name.new(rrset.name.labels.last(sig.labels), true).to_s(true))
          else
            rrset.name
          end
        single = Dnsruby::RRSet.new
        rrset.rrs.each do |rr|
          copy = rr.clone
          copy.name = owner
          single.add(copy, false)
        end
        sig_copy = sig.clone
        sig_copy.name = owner
        single.add(sig_copy, false)
        single
      end

      def usable_ds(ds_records)
        ds_records.select do |d|
          SUPPORTED_ALGORITHMS.include?(d.algorithm.code) &&
            SUPPORTED_DS_DIGESTS.include?(d.digest_type.code)
        end
      end

      # ----- cache and small helpers -----------------------------------

      def cache_get(key)
        @lock.synchronize do
          entry = @zone_cache[key]
          entry && entry[:expires] > monotime ? entry[:value] : nil
        end
      end

      def cache_put(key, value)
        ttl = value[:status] == :secure ? (value[:ttl] || SECURE_CACHE_TTL_CAP) : INSECURE_CACHE_TTL
        return value if value[:status] == :bogus # never pin an attack in cache

        @lock.synchronize { @zone_cache[key] = { value: value, expires: monotime + ttl } }
        value
      end

      def monotime
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def bogus(reason)
        Answer.new(status: :bogus, records: [], reason: reason)
      end

      def worst_status(a, b)
        order = { bogus: 0, insecure: 1, secure: 2 }
        order[a] <= order[b] ? a : b
      end

      def to_name(name)
        return Dnsruby::Name.new(name.labels, true) if name.is_a?(Dnsruby::Name)

        Dnsruby::Name.create(name.to_s.end_with?(".") ? name.to_s : "#{name}.")
      end

      def ancestor_or_equal?(ancestor, name)
        a = ancestor.labels.map { |l| l.to_s.downcase }
        n = name.labels.map { |l| l.to_s.downcase }
        n.length >= a.length && n.last(a.length) == a
      end

      def strict_ancestor?(ancestor, name)
        ancestor.labels.length < name.labels.length && ancestor_or_equal?(ancestor, name)
      end
    end
  end
end
