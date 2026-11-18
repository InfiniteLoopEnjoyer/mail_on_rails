# frozen_string_literal: true

module MailOnRails
  module Dnssec
    # A validating stub forwarder: queries an upstream recursive with CD
    # set (so nothing is filtered on our behalf) and validates everything
    # in process - RRSIG chains walked zone by zone up to the root trust
    # anchor, denials proven with NSEC/NSEC3 - so upstream needs no trust
    # at all. SenderAuth::Dns rides this for the outbound DANE
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
    # verifications, NSEC3 hashes, denial-record counts and wall-clock
    # time are budgeted per resolve() and trip to :bogus - a pure-Ruby
    # validator must never let a response buy unbounded CPU. For the
    # same reason resolve() answers :bogus, not an exception, when a
    # response or a name turns out to be something the code cannot
    # handle: the only error callers see is Transport::TempError.
    class Resolver
      Answer = Struct.new(:status, :records, :proof, :reason, keyword_init: true)

      MAX_QUERIES = 32          # chain walks are ~2 per zone cut; 32 is generous
      MAX_CRYPTO = 64           # signature verifications per resolve
      MAX_SIGS_PER_RRSET = 4    # (sig, key) pairs attempted per RRset
      MAX_KEYS_PER_SIG = 3
      MAX_DNSKEYS = 16          # larger DNSKEY RRsets are hostile, not real
      MAX_DENIAL_RECORDS = 24
      # NSEC3 hashes computed per resolve, each at most
      # Nsec3Proof::MAX_ITERATIONS + 1 digests. An honest denial needs
      # one per label between qname and its zone apex, plus the wildcard.
      MAX_NSEC3_HASHES = 64
      # Wall-clock seconds per resolve, checked wherever another budget
      # is charged: the caps above bound the work, this bounds the
      # waiting (a slow upstream times out per query, per server).
      MAX_SECONDS = 20
      MAX_CNAME_DEPTH = 8
      MAX_CHAIN_DEPTH = 16
      INSECURE_CACHE_TTL = 300
      SECURE_CACHE_TTL_CAP = 3600
      ZONE_CACHE_MAX = 4096     # entries; expired ones are swept, then the oldest go

      # DS records naming algorithms we cannot verify make the zone
      # insecure, not bogus (RFC 4035 section 5.2) - so the usable set
      # is exactly what Signature.verify can do.
      SUPPORTED_ALGORITHMS = Signature::ALGORITHMS
      SUPPORTED_DS_DIGESTS = [ 1, 2, 4 ].freeze

      class Budget
        class Exceeded < StandardError; end

        def initialize(queries: MAX_QUERIES, crypto: MAX_CRYPTO, nsec3_hashes: MAX_NSEC3_HASHES,
                       seconds: MAX_SECONDS)
          @queries = queries
          @crypto = crypto
          @nsec3_hashes = nsec3_hashes
          @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
        end

        def query!
          @queries -= 1
          raise Exceeded, "query budget exhausted" if @queries.negative?

          on_time!
        end

        def crypto!
          @crypto -= 1
          raise Exceeded, "crypto budget exhausted" if @crypto.negative?

          on_time!
        end

        def nsec3_hash!
          @nsec3_hashes -= 1
          raise Exceeded, "NSEC3 hash budget exhausted" if @nsec3_hashes.negative?

          on_time!
        end

        private

        def on_time!
          return if Process.clock_gettime(Process::CLOCK_MONOTONIC) <= @deadline

          raise Exceeded, "time budget exhausted"
        end
      end

      Ctx = Struct.new(:budget, :now, :stack, :hasher)

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
        budget = Budget.new(**@budget_opts)
        ctx = Ctx.new(budget, @now.call, [], Nsec3Proof::Hasher.new { budget.nsec3_hash! })
        chase(to_name(qname), Dnsruby::Types.new(qtype), ctx, 0)
      rescue Budget::Exceeded => e
        Answer.new(status: :bogus, records: [], reason: "resource budget exceeded (#{e.message}) - hostile response shape?")
      rescue Transport::TempError
        raise
      rescue Dnsruby::ResolvError => e
        # A name DNS cannot carry (over 255 octets, a 64-octet label):
        # "_25._tcp." in front of a maximal MX target is enough. Nothing
        # can be published there, but "nothing" is not ours to assert.
        bogus("unusable name: #{e.message}")
      rescue StandardError => e
        # Records arrive from whoever answers; a shape nothing above
        # anticipated must cost that party a verdict, not hand the
        # caller an exception it never planned for.
        bogus("validation aborted (#{e.class}: #{e.message})")
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

        signers = signers_of(sigs).select { |name| ancestor_or_equal?(name, qname) }
        if signers.empty?
          return bogus("RRSIG signer #{to_name(sigs[0].signers_name)} is out of bailiwick for #{qname}")
        end

        # Anyone on the path can add RRSIGs naming whichever ancestor
        # they like, so the first one is no guide to the real signer:
        # each zone named gets its turn, and a verdict other than :bogus
        # stands on that zone's own chain of trust.
        failure = nil
        signers.each do |signer|
          answer = validate_signed(msg, rrset, qname, signer, ctx)
          return answer unless answer.status == :bogus

          failure ||= answer
        end
        failure
      end

      def validate_signed(msg, rrset, qname, signer, ctx)
        zone = zone_keys(signer, ctx)
        case zone[:status]
        when :insecure
          Answer.new(status: :insecure, records: rrset.rrs,
                     reason: "zone #{signer} is outside the chain of trust")
        when :bogus
          bogus(zone[:reason] || "chain of trust to #{signer} failed")
        else
          # The one place a wildcard-expanded signature is welcome - and
          # only together with the proof that nothing closer exists.
          sig = verify_with_keys(rrset, zone[:keys], signer, ctx, wildcard: true)
          return bogus("signature on #{qname}/#{rrset.type} failed to verify") unless sig

          if wildcard_expanded?(sig, qname)
            wildcard_status = wildcard_proof_status(msg, qname, sig.labels, zone[:keys], signer, ctx)
            return bogus("wildcard expansion for #{qname} is unproven") unless wildcard_status

            return Answer.new(status: wildcard_status, records: rrset.rrs, proof: :wildcard_answer)
          end
          Answer.new(status: :secure, records: rrset.rrs)
        end
      end

      def wildcard_proof_status(msg, qname, rrsig_labels, keys, zone, ctx)
        nsec3s, nsecs, unusable = verified_denial_records(msg, keys, zone, ctx)
        result = Nsec3Proof.wildcard_answer(qname, rrsig_labels, nsec3s, hasher: ctx.hasher) ||
                 NsecProof.wildcard_answer(qname, rrsig_labels, nsecs)
        if result.nil? && only_unusable_nsec3?(nsec3s, nsecs, unusable)
          return over_iterated_status(zone, qname, ctx) == :insecure ? :insecure : nil
        end

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

        nsec3s, nsecs, unusable = verified_denial_records(msg, zone[:keys], zone_name, ctx)
        result =
          if msg.rcode == Dnsruby::RCode.NXDOMAIN
            Nsec3Proof.name_error(qname, nsec3s, hasher: ctx.hasher) ||
              NsecProof.name_error(qname, nsecs)
          else
            Nsec3Proof.no_data(qname, qtype, nsec3s, hasher: ctx.hasher) ||
              Nsec3Proof.wildcard_no_data(qname, qtype, nsec3s, hasher: ctx.hasher) ||
              NsecProof.no_data(qname, qtype, nsecs)
          end
        unless result
          # RFC 9276 section 3.2: a zone whose NSEC3 iteration count is
          # over the cap is treated as unsigned, not broken - :bogus
          # (defer) is reserved for material that verified and still
          # proves nothing, or that failed to verify.
          if only_unusable_nsec3?(nsec3s, nsecs, unusable)
            unless over_iterated_status(zone_name, qname, ctx) == :insecure
              return bogus("NSEC3 records for #{zone_name} exceed #{Nsec3Proof::MAX_ITERATIONS} iterations, " \
                           "and #{qname} is not shown to be that zone's to deny")
            end

            return Answer.new(status: :insecure, records: [],
                              reason: "NSEC3 records for #{zone_name} exceed #{Nsec3Proof::MAX_ITERATIONS} iterations")
          end

          return bogus("denial of #{qname}/#{qtype} is unproven")
        end

        Answer.new(status: result.status, records: [], proof: result.proof)
      end

      # Whether +zone+'s over-iterated NSEC3s may stand as "insecure" for
      # +name+. They are the one denial accepted without being checked
      # against the name, so an ancestor's would otherwise do for any
      # name beneath it - a signed child zone included. The DS walk from
      # the zone down to the name settles whose name it is: a signed
      # delegation on the way means a child zone answers for it, and the
      # records were borrowed. +upto+ is the label count the walk ends
      # at (the whole name unless the caller is asking about the name's
      # own DS).
      def over_iterated_status(zone, name, ctx, upto: name.labels.length)
        ((zone.labels.length + 1)..upto).each do |count|
          cut = Dnsruby::Name.new(name.labels.last(count), true)
          case ds_for(cut, ctx)[:status]
          when :insecure then return :insecure # unsigned from here down, whoever serves it
          when :secure, :nxdomain, :bogus then return :bogus
          end
          # :continue - still inside +zone+, keep descending.
        end
        :insecure
      end

      # NSEC/NSEC3 RRsets are only proof material once their own
      # signatures verify under the zone's keys - an attacker can inject
      # authority records freely, so unverified ones are dropped, and
      # the total is capped. The signature must be over the owner as
      # given: the genuine NSEC at "*.example.com" also verifies, as a
      # wildcard expansion, under any owner beneath example.com, and a
      # proof would then take that owner's word for what exists.
      #
      # Returns [usable NSEC3s, NSECs, count of verified NSEC3s dropped
      # as unusable] - the last so the caller can tell "over-iterated
      # zone" from "no proof at all".
      def verified_denial_records(msg, keys, zone, ctx)
        nsec3s = []
        nsecs = []
        total = 0
        (msg.authority.rrsets("NSEC3") + msg.authority.rrsets("NSEC")).each do |rrset|
          next if rrset.rrs.empty?
          next if (total += rrset.rrs.length) > MAX_DENIAL_RECORDS
          # An NSEC3 owner is one hash label on the zone apex (RFC 5155
          # section 3); the proofs take the zone from it.
          next if rrset.type == Dnsruby::Types.NSEC3 && rrset.name.labels.length != zone.labels.length + 1
          next unless verify_with_keys(rrset, keys, zone, ctx)

          (rrset.type == Dnsruby::Types.NSEC3 ? nsec3s : nsecs).concat(rrset.rrs)
        end
        usable = Nsec3Proof.usable(nsec3s)
        [ usable, nsecs, nsec3s.length - usable.length ]
      end

      # Every verified denial record was an NSEC3 the validator refuses to
      # hash (RFC 9276): there is nothing left to judge the denial by.
      def only_unusable_nsec3?(nsec3s, nsecs, unusable)
        nsec3s.empty? && nsecs.empty? && unusable.positive?
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
        sig = verify_with_keys(krrset, ksks, zone, ctx)
        return { status: :bogus, reason: "DNSKEY RRset of #{zone} failed to verify" } unless sig

        # Kept no longer than either link (DS, DNSKEY) stays verifiable.
        ttl = [ @cache_ttl_cap, trust_ttl(krrset, sig, ctx), ds[:ttl] ].compact.min
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

        parents = signers_of(sigs).select { |name| strict_ancestor?(name, zone) }
        if parents.empty?
          return { status: :bogus, reason: "DS for #{zone} signed by non-ancestor #{to_name(sigs[0].signers_name)}" }
        end

        # As in validate_positive: every ancestor an RRSIG names is tried.
        failure = nil
        parents.each do |parent|
          result = verified_ds(ds_rrset, zone, parent, ctx)
          return result unless result[:status] == :bogus

          failure ||= result
        end
        failure
      end

      def verified_ds(ds_rrset, zone, parent, ctx)
        pkeys = zone_keys(parent, ctx)
        case pkeys[:status]
        when :insecure then return { status: :insecure }
        when :bogus then return { status: :bogus, reason: pkeys[:reason] }
        end
        sig = verify_with_keys(ds_rrset, pkeys[:keys], parent, ctx)
        return { status: :bogus, reason: "DS RRset for #{zone} failed to verify" } unless sig

        usable = usable_ds(ds_rrset.rrs)
        # All-unsupported-algorithms is a provably unverifiable zone:
        # insecure, not bogus (RFC 4035 section 5.2).
        usable.empty? ? { status: :insecure } : { status: :secure, ds: usable, ttl: trust_ttl(ds_rrset, sig, ctx) }
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

        nsec3s, nsecs, unusable = verified_denial_records(msg, pkeys[:keys], parent, ctx)

        # RFC 9276 section 3.2, the way validate_negative reads it: an
        # over-iterated parent is treated as unsigned, so it cannot deny
        # a DS any more securely than it denies anything else - and,
        # likewise, only where the name between here and there is its
        # own.
        if only_unusable_nsec3?(nsec3s, nsecs, unusable)
          if over_iterated_status(parent, zone, ctx, upto: zone.labels.length - 1) == :insecure
            return { status: :insecure }
          end

          return { status: :bogus, reason: "DS denial for #{zone} rests on over-iterated NSEC3 records " \
                                           "of #{parent}, which a signed delegation separates from it" }
        end

        if msg.rcode == Dnsruby::RCode.NXDOMAIN
          result = Nsec3Proof.name_error(zone, nsec3s, hasher: ctx.hasher) ||
                   NsecProof.name_error(zone, nsecs)
          return { status: :bogus, reason: "DS NXDOMAIN for #{zone} is unproven" } unless result

          return { status: result.status == :secure ? :nxdomain : :insecure }
        end

        ds_nodata_status(zone, nsec3s, nsecs, ctx)
      end

      # NODATA for DS, distinguished by the matching record's bitmap: NS
      # present means an unsigned delegation (:insecure); absent means
      # no zone cut here (:continue); an Opt-Out span could hide either
      # (:insecure, conservatively).
      def ds_nodata_status(zone, nsec3s, nsecs, ctx)
        hasher = ctx.hasher
        if (m = nsec3s.find { |rr| Nsec3Proof.matches?(rr, zone, hasher: hasher) })
          return { status: :bogus, reason: "NSEC3 for #{zone} claims DS exists" } if m.types.include?("DS")

          return { status: m.types.include?("NS") ? :insecure : :continue }
        end
        if (ce = Nsec3Proof.closest_encloser_proof(zone, nsec3s, hasher: hasher))
          return { status: :insecure } if ce[:covering].opt_out?
        end

        if (m = nsecs.find { |rr| NsecProof.matches?(rr, zone) })
          return { status: :bogus, reason: "NSEC for #{zone} claims DS exists" } if m.types.include?("DS")

          return { status: m.types.include?("NS") ? :insecure : :continue }
        end
        # Neither a wildcard-synthesized DS NODATA nor an empty
        # non-terminal can be a delegation.
        if Nsec3Proof.wildcard_no_data(zone, Dnsruby::Types.DS, nsec3s, hasher: hasher) ||
           NsecProof.no_data(zone, Dnsruby::Types.DS, nsecs)
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
      #
      # A signature made over "*.<ancestor>" verifies under every owner
      # that wildcard could expand to (RFC 4035 section 5.3.2), which is
      # right for an answer whose caller then demands the no-closer-match
      # proof and wrong for everything whose owner is itself evidence:
      # NSEC and NSEC3 (the owner says what exists), SOA (which zone is
      # speaking), DS and DNSKEY (which zone the keys are for). Unless
      # +wildcard+ is set, only an RRSIG over the owner as given counts.
      #
      # RRSIGs that could not verify here whatever their signature says
      # - another signer, a key this zone does not have, a lapsed window
      # - are passed over before the per-RRset cap is counted, so
      # prepending junk cannot crowd the real one out; the crypto budget
      # remains the bound on work.
      def verify_with_keys(rrset, keys, expected_signer, ctx, wildcard: false)
        expected = expected_signer.canonical
        owner = rrset.name
        attempts = 0
        rrset.sigs.each do |sig|
          next unless to_name(sig.signers_name).canonical == expected
          next if sig.labels > owner.labels.length # RFC 4035 5.3.1
          next if !wildcard && wildcard_expanded?(sig, owner)
          next unless Signature.valid_at?(sig, ctx.now)

          candidates = keys.select { |k| k.key_tag == sig.key_tag && k.algorithm == sig.algorithm }
          next if candidates.empty?
          break if (attempts += 1) > MAX_SIGS_PER_RRSET

          candidates.first(MAX_KEYS_PER_SIG).each do |key|
            ctx.budget.crypto!
            return sig if Signature.verify(rrset, sig, key, now: ctx.now)
          end
        end
        nil
      end

      # RFC 4035 section 5.3.2: fewer Labels than the owner has (a
      # literal leading "*" is not counted) means the RRset was
      # synthesized from a wildcard.
      def wildcard_expanded?(sig, owner)
        sig.labels < owner.labels.length - (owner.wild? ? 1 : 0)
      end

      # The distinct zones a set of RRSIGs names, deepest first - the
      # most specific zone is the one with authority over the name.
      def signers_of(sigs)
        sigs.map { |sig| to_name(sig.signers_name) }
            .uniq(&:canonical)
            .sort_by { |name| -name.labels.length }
      end

      # How long a verified RRset may be relied on (RFC 4035 section
      # 5.3.3): its TTL, capped by the RRSIG's Original TTL (the TTL in
      # the response is not signed) and by the signature's remaining
      # validity.
      def trust_ttl(rrset, sig, ctx)
        [ rrset.ttl, sig.original_ttl, Signature.expires_in(sig, ctx.now) ].min
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

        @lock.synchronize do
          now = monotime
          if @zone_cache.size >= ZONE_CACHE_MAX
            @zone_cache.delete_if { |_zone, entry| entry[:expires] <= now }
            @zone_cache.shift while @zone_cache.size >= ZONE_CACHE_MAX # insertion order: oldest first
          end
          @zone_cache[key] = { value: value, expires: now + ttl }
        end
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
