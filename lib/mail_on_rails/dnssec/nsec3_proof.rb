# frozen_string_literal: true

module MailOnRails
  module Dnssec
    # Authenticated denial of existence with NSEC3 (RFC 5155 section 8).
    #
    # Each prover takes the qname/qtype plus the NSEC3 RRs from a
    # response's authority section and returns a Result when the records
    # prove the claim, nil when they do not; the caller decides whether
    # nil is bogus or merely unproven. Verifying the RRSIGs over those
    # NSEC3 RRs is not this module's job - the proofs assume the records
    # are authentic and only ask what they prove.
    #
    # Result#status is :secure or :insecure. :insecure means the proof
    # rests on an Opt-Out span (RFC 5155 section 6): the name provably
    # has no signed data, but an unsigned delegation could still exist
    # inside the span, so a consumer like DANE (RFC 7672 section 2.2)
    # must treat the name as outside DNSSEC rather than securely absent.
    #
    # The record-level questions (does this NSEC3 match a name, cover
    # it, speak for a delegation) are module functions over
    # Dnsruby::RR::NSEC3, like NsecProof's - dnsruby is the codec and
    # the section 5 hash, nothing here reopens its classes.
    module Nsec3Proof
      Result = Struct.new(:proof, :status, :closest_encloser, keyword_init: true)

      # RFC 9276 section 3.2: a validator SHOULD treat responses whose
      # NSEC3 iteration count exceeds 100 as insecure rather than spend
      # the CPU (an attacker-amplifiable cost) validating them.
      MAX_ITERATIONS = 100

      module_function

      def records(msg)
        msg.authority.rrsets("NSEC3").flat_map(&:rrs)
      end

      def usable(nsec3s)
        nsec3s.select { |rr| usable?(rr) }
      end

      # RFC 5155 section 8.3: the longest ancestor of +qname+ that an NSEC3
      # proves to exist (the closest encloser), plus a record covering the
      # next-closer name - together establishing that qname itself does
      # not exist. Returns {closest_encloser:, matching:, covering:}, or
      # nil when the records prove no such thing - including when qname
      # itself matches (it exists) or the would-be encloser is an ancestor
      # delegation (the child zone is authoritative below it).
      def closest_encloser_proof(qname, nsec3s)
        labels = qname.labels
        labels.each_index do |i|
          candidate = Dnsruby::Name.new(labels[i..], true)
          matching = nsec3s.find { |rr| matches?(rr, candidate) }
          next unless matching
          return nil if i.zero? || ancestor_delegation?(matching)

          covering = nsec3s.find { |rr| covers?(rr, Dnsruby::Name.new(labels[(i - 1)..], true)) }
          return nil unless covering

          return { closest_encloser: candidate, matching: matching, covering: covering }
        end
        nil
      end

      # RFC 5155 section 8.4 (name error): qname does not exist and no
      # wildcard could have synthesized it.
      def name_error(qname, nsec3s)
        ce = closest_encloser_proof(qname, nsec3s)
        return nil unless ce
        return nil unless nsec3s.any? { |rr| covers?(rr, wildcard_of(ce[:closest_encloser])) }

        Result.new(proof: :name_error, status: opt_out_status(ce), closest_encloser: ce[:closest_encloser])
      end

      # RFC 5155 sections 8.5-8.6 (no data): qname exists but has neither
      # qtype nor a CNAME. For DS, an Opt-Out span across the name proves
      # only that no *signed* delegation exists - hence :insecure.
      def no_data(qname, qtype, nsec3s)
        matching = nsec3s.find { |rr| matches?(rr, qname) }
        if matching
          return nil if matching.types.include?(qtype) || matching.types.include?("CNAME")
          # The parent side of a delegation owns nothing at that name but DS.
          return nil if ancestor_delegation?(matching) && qtype != Dnsruby::Types.DS

          return Result.new(proof: :no_data, status: :secure)
        end

        if qtype == Dnsruby::Types.DS
          ce = closest_encloser_proof(qname, nsec3s)
          if ce && ce[:covering].opt_out?
            return Result.new(proof: :no_data, status: :insecure, closest_encloser: ce[:closest_encloser])
          end
        end
        nil
      end

      # RFC 5155 section 8.7 (wildcard no data): qname would match a
      # wildcard, but the wildcard lacks qtype.
      def wildcard_no_data(qname, qtype, nsec3s)
        ce = closest_encloser_proof(qname, nsec3s)
        return nil unless ce

        matching = nsec3s.find { |rr| matches?(rr, wildcard_of(ce[:closest_encloser])) }
        return nil unless matching
        return nil if matching.types.include?(qtype) || matching.types.include?("CNAME")

        Result.new(proof: :wildcard_no_data, status: opt_out_status(ce), closest_encloser: ce[:closest_encloser])
      end

      # RFC 5155 section 8.8 (wildcard answer): the answer was synthesized
      # from a wildcard - the RRSIG's Labels field says how many labels the
      # source owner had - so the proof is that nothing closer than the
      # wildcard's parent exists for qname.
      def wildcard_answer(qname, rrsig_labels, nsec3s)
        return nil if rrsig_labels >= qname.labels.length

        next_closer = Dnsruby::Name.new(qname.labels.last(rrsig_labels + 1), true)
        covering = nsec3s.find { |rr| covers?(rr, next_closer) }
        return nil unless covering

        Result.new(proof: :wildcard_answer, status: covering.opt_out? ? :insecure : :secure)
      end

      # RFC 5155 section 8.9: a referral to an unsigned child zone is
      # legitimate when an NSEC3 matches the delegation with NS set but DS
      # and SOA clear, or when the delegation falls inside an Opt-Out span.
      # Either way the child is provably outside DNSSEC: always :insecure.
      def referral(delegation, nsec3s)
        matching = nsec3s.find { |rr| matches?(rr, delegation) }
        if matching
          unless matching.types.include?("NS") &&
                 !matching.types.include?("DS") && !matching.types.include?("SOA")
            return nil
          end
          return Result.new(proof: :referral, status: :insecure)
        end

        ce = closest_encloser_proof(delegation, nsec3s)
        return nil unless ce && ce[:covering].opt_out?

        Result.new(proof: :referral, status: :insecure, closest_encloser: ce[:closest_encloser])
      end

      # Checks the denial story of a whole response: picks the applicable
      # section 8 proof from rcode and shape, raises VerifyError when NSEC3
      # records are present but prove nothing, and returns the Result (nil
      # when no denial proof was required). A response whose NSEC3 records
      # are all unusable (unknown algorithm, oversized iteration count) is
      # :insecure, never bogus (RFC 9276 section 3.2).
      def verify(msg)
        question = msg.question[0]
        return nil unless question

        qname = Dnsruby::Name.new(question.qname.labels, true)
        qtype = question.qtype
        all = records(msg)
        return nil if all.empty?

        nsec3s = usable(all)
        return Result.new(proof: :none, status: :insecure) if nsec3s.empty?

        if msg.rcode == Dnsruby::RCode.NXDOMAIN
          return name_error(qname, nsec3s) ||
                 raise(Dnsruby::VerifyError.new("NSEC3 RRs do not prove the nonexistence of #{qname}"))
        end
        return nil unless msg.rcode == Dnsruby::RCode.NOERROR

        answer_rrset = msg.answer.rrset(qname, qtype)
        if answer_rrset.length > 0
          sig = answer_rrset.sigs[0]
          return nil if sig.nil? || sig.labels >= qname.labels.length # not wildcard-expanded

          return wildcard_answer(qname, sig.labels, nsec3s) ||
                 raise(Dnsruby::VerifyError.new("NSEC3 RRs do not prove the wildcard expansion for #{qname}"))
        end
        return nil if msg.answer.length > 0 # CNAME toward the answer; denial applies to its target, not qname

        ns_rrset = msg.authority.rrsets("NS")[0]
        soa_rrset = msg.authority.rrsets("SOA")[0]
        if ns_rrset && ns_rrset.length > 0 && (soa_rrset.nil? || soa_rrset.length == 0) && qtype != Dnsruby::Types.DS
          return referral(Dnsruby::Name.new(ns_rrset.name.labels, true), nsec3s) ||
                 raise(Dnsruby::VerifyError.new("NSEC3 RRs do not prove the referral to #{ns_rrset.name}"))
        end

        no_data(qname, qtype, nsec3s) || wildcard_no_data(qname, qtype, nsec3s) ||
          raise(Dnsruby::VerifyError.new("NSEC3 RRs do not prove the absence of #{qtype} at #{qname}"))
      end

      # "*.<name>", built from labels so the root needs no special case.
      def wildcard_of(name)
        Dnsruby::Name.new([ Dnsruby::Name::Label.new("*") ] + name.labels, true)
      end

      def opt_out_status(ce)
        ce[:covering].opt_out? ? :insecure : :secure
      end

      # ----- record-level primitives (RFC 5155 section 8.2) ------------

      # A record the proofs may lean on: SHA-1 hashing (the only
      # algorithm defined), no flag beyond Opt-Out (section 8.2: records
      # with unknown flags MUST be ignored), an iteration count under
      # the cap, and an owner that has a zone under its hash label.
      def usable?(rr)
        Dnsruby::Nsec3HashAlgorithms.SHA_1 == rr.hash_alg &&
          [ 0, Dnsruby::RR::NSEC3::OPT_OUT ].include?(rr.flags) &&
          rr.iterations <= MAX_ITERATIONS &&
          rr.name.labels.length >= 2
      end

      # The owner's first label: the base32hex hash the record is about.
      def hashed_owner(rr)
        rr.name.labels[0].to_s.downcase
      end

      # Base32hex hash of +name+ under the record's parameters, or nil
      # when the record is unusable or the name lies outside its zone.
      def hash_of(rr, name)
        return nil unless usable?(rr)

        name = to_name(name)
        return nil unless in_zone?(rr, name)

        # salt reads back in presentation form ("-" when empty).
        salt = Dnsruby::RR::NSEC3.decode_salt(rr.salt)
        Dnsruby::RR::NSEC3.calculate_hash(name, rr.iterations, salt, rr.hash_alg)
      end

      # The record's owner hash is the hash of +name+: the name exists,
      # and the type bitmap enumerates its types.
      def matches?(rr, name)
        hash_of(rr, name) == hashed_owner(rr)
      end

      # The hash of +name+ falls strictly between the owner hash and
      # next_hashed: the name does not exist (or, under Opt-Out, has no
      # signed records). The chain is circular - the last record wraps
      # to the first, and owner == next is a single-record chain
      # covering everything but itself. base32hex preserves the sort
      # order of the raw digests, so string comparison suffices.
      def covers?(rr, name)
        hash = hash_of(rr, name)
        return false unless hash

        owner = hashed_owner(rr)
        succ = Dnsruby::RR::NSEC3.encode_next_hashed(rr.next_hashed)
        if owner < succ
          owner < hash && hash < succ
        else
          hash > owner || hash < succ
        end
      end

      # RFC 6840 section 4.4 applied to NSEC3: a record for a delegation
      # point (NS without SOA) or a DNAME proves nothing about names
      # below it - the child zone is authoritative there. Such a record
      # must not act as a closest encloser or prove no-data for anything
      # but DS.
      def ancestor_delegation?(rr)
        (rr.types.include?("NS") && !rr.types.include?("SOA")) || rr.types.include?("DNAME")
      end

      def to_name(name)
        name.is_a?(Dnsruby::Name) ? name : Dnsruby::Name.create(name)
      end

      def in_zone?(rr, name)
        zone_labels = rr.name.labels[1..].map { |label| label.to_s.downcase }
        name_labels = name.labels.map { |label| label.to_s.downcase }
        name_labels.length >= zone_labels.length && name_labels.last(zone_labels.length) == zone_labels
      end
    end
  end
end
