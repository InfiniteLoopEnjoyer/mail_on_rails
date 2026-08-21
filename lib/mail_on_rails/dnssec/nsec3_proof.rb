# frozen_string_literal: true

module Dnsruby
  # Authenticated denial of existence with NSEC3 - the RFC 5155 section 8
  # proofs missing from dnsruby's SingleVerifier.
  #
  # Each prover takes the qname/qtype plus the NSEC3 RRs from a response's
  # authority section and returns a Result when the records prove the
  # claim, nil when they do not; the caller decides whether nil is bogus
  # (raise) or merely unproven. Verifying the RRSIGs over those NSEC3 RRs
  # is not this module's job - SingleVerifier#verify checks every
  # authority RRset's signature separately; these proofs assume the
  # records are authentic and only ask what they prove.
  #
  # Result#status is :secure or :insecure. :insecure means the proof
  # rests on an Opt-Out span (RFC 5155 section 6): the name provably has
  # no signed data, but an unsigned delegation could still exist inside
  # the span, so a consumer like DANE (RFC 7672 section 2.2) must treat
  # the name as outside DNSSEC rather than securely absent.
  module Nsec3Proof
    Result = Struct.new(:proof, :status, :closest_encloser, keyword_init: true)

    module_function

    def records(msg)
      msg.authority.rrsets("NSEC3").flat_map(&:rrs)
    end

    def usable(nsec3s)
      nsec3s.select(&:usable_for_proofs?)
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
        candidate = Name.new(labels[i..], true)
        matching = nsec3s.find { |rr| rr.matches?(candidate) }
        next unless matching
        return nil if i.zero? || matching.ancestor_delegation?

        covering = nsec3s.find { |rr| rr.covers?(Name.new(labels[(i - 1)..], true)) }
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
      return nil unless nsec3s.any? { |rr| rr.covers?(wildcard_of(ce[:closest_encloser])) }

      Result.new(proof: :name_error, status: opt_out_status(ce), closest_encloser: ce[:closest_encloser])
    end

    # RFC 5155 sections 8.5-8.6 (no data): qname exists but has neither
    # qtype nor a CNAME. For DS, an Opt-Out span across the name proves
    # only that no *signed* delegation exists - hence :insecure.
    def no_data(qname, qtype, nsec3s)
      matching = nsec3s.find { |rr| rr.matches?(qname) }
      if matching
        return nil if matching.types.include?(qtype) || matching.types.include?("CNAME")
        # The parent side of a delegation owns nothing at that name but DS.
        return nil if matching.ancestor_delegation? && qtype != Types.DS

        return Result.new(proof: :no_data, status: :secure)
      end

      if qtype == Types.DS
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

      matching = nsec3s.find { |rr| rr.matches?(wildcard_of(ce[:closest_encloser])) }
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

      next_closer = Name.new(qname.labels.last(rrsig_labels + 1), true)
      covering = nsec3s.find { |rr| rr.covers?(next_closer) }
      return nil unless covering

      Result.new(proof: :wildcard_answer, status: covering.opt_out? ? :insecure : :secure)
    end

    # RFC 5155 section 8.9: a referral to an unsigned child zone is
    # legitimate when an NSEC3 matches the delegation with NS set but DS
    # and SOA clear, or when the delegation falls inside an Opt-Out span.
    # Either way the child is provably outside DNSSEC: always :insecure.
    def referral(delegation, nsec3s)
      matching = nsec3s.find { |rr| rr.matches?(delegation) }
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

      qname = Name.new(question.qname.labels, true)
      qtype = question.qtype
      all = records(msg)
      return nil if all.empty?

      nsec3s = usable(all)
      return Result.new(proof: :none, status: :insecure) if nsec3s.empty?

      if msg.rcode == RCode.NXDOMAIN
        return name_error(qname, nsec3s) ||
               raise(VerifyError.new("NSEC3 RRs do not prove the nonexistence of #{qname}"))
      end
      return nil unless msg.rcode == RCode.NOERROR

      answer_rrset = msg.answer.rrset(qname, qtype)
      if answer_rrset.length > 0
        sig = answer_rrset.sigs[0]
        return nil if sig.nil? || sig.labels >= qname.labels.length # not wildcard-expanded

        return wildcard_answer(qname, sig.labels, nsec3s) ||
               raise(VerifyError.new("NSEC3 RRs do not prove the wildcard expansion for #{qname}"))
      end
      return nil if msg.answer.length > 0 # CNAME toward the answer; denial applies to its target, not qname

      ns_rrset = msg.authority.rrsets("NS")[0]
      soa_rrset = msg.authority.rrsets("SOA")[0]
      if ns_rrset && ns_rrset.length > 0 && (soa_rrset.nil? || soa_rrset.length == 0) && qtype != Types.DS
        return referral(Name.new(ns_rrset.name.labels, true), nsec3s) ||
               raise(VerifyError.new("NSEC3 RRs do not prove the referral to #{ns_rrset.name}"))
      end

      no_data(qname, qtype, nsec3s) || wildcard_no_data(qname, qtype, nsec3s) ||
        raise(VerifyError.new("NSEC3 RRs do not prove the absence of #{qtype} at #{qname}"))
    end

    def wildcard_of(name)
      Name.create("*.#{name}.")
    end

    def opt_out_status(ce)
      ce[:covering].opt_out? ? :insecure : :secure
    end
  end
end
