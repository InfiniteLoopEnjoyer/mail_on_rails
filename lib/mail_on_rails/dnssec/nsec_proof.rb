# frozen_string_literal: true

module MailOnRails
  module Dnssec
    # Authenticated denial of existence with plain NSEC (RFC 4035
    # sections 3.1.3/5.4), shaped like Nsec3Proof: provers take
    # qname/qtype plus the NSEC RRs from a response's authority section
    # and return a Result or nil, the caller deciding whether nil is
    # bogus. Signature verification of the NSEC RRs themselves is the
    # caller's job.
    #
    # NSEC has no Opt-Out, so proofs are :secure whenever they hold -
    # the Result shape just stays parallel to Nsec3Proof so consumers
    # treat the two schemes interchangeably. Aggressively minimal
    # responders (Cloudflare-style "black lies") produce ordinary
    # no-data shapes here.
    module NsecProof
      Result = Struct.new(:proof, :status, :closest_encloser, keyword_init: true)

      module_function

      def records(msg)
        msg.authority.rrsets("NSEC").flat_map(&:rrs)
      end

      # Canonical-order strict comparison. Name#canonically_before returns
      # true for equal names, so equality is excluded explicitly.
      def strictly_before?(a, b)
        a.canonical != b.canonical && a.canonically_before(b)
      end

      def matches?(nsec, name)
        nsec.name.canonical == to_name(name).canonical
      end

      # +name+ falls in the gap this NSEC spans. The zone's last NSEC wraps:
      # its next_domain is the apex, which sorts before (or equal to) the
      # owner, and everything in the zone after the owner is covered.
      def covers?(nsec, name)
        name = to_name(name)
        owner = nsec.name
        succ = nsec.next_domain
        return false if name.canonical == owner.canonical

        if strictly_before?(owner, succ)
          strictly_before?(owner, name) && strictly_before?(name, succ)
        else
          # Wrapped (or single-NSEC zone): next_domain is the apex; the
          # name must be inside the zone and after the owner.
          in_zone?(name, succ) && strictly_before?(owner, name)
        end
      end

      # RFC 6840 section 4.1: an NSEC for a delegation point (NS without
      # SOA) or a DNAME proves nothing about names below it.
      def ancestor_delegation?(nsec)
        (nsec.types.include?("NS") && !nsec.types.include?("SOA")) || nsec.types.include?("DNAME")
      end

      # +nsec+ covers +name+ and has the standing to deny it. A
      # delegation's NSEC is silent only about what lies beneath its own
      # owner - the child zone speaks there - and proves the rest of its
      # gap like any other. In a zone made of delegations (the root, a
      # TLD) nearly every denial rests on one.
      #
      # A gap whose far end lies beneath +name+ denies nothing either:
      # that is an empty non-terminal, a name that exists.
      def proves_absent?(nsec, name)
        name = to_name(name)
        covers?(nsec, name) && !in_zone?(nsec.next_domain, name) &&
          !(ancestor_delegation?(nsec) && in_zone?(name, nsec.name))
      end

      # RFC 4592 section 2.2.2 (and RFC 4035 section 3.1.3.1 read with
      # it): +name+ sorts inside this NSEC's gap and the next name is one
      # of its descendants, so +name+ exists as an empty non-terminal -
      # it owns no RRset of any type, and no wildcard can stand in for
      # it.
      def empty_non_terminal?(nsec, name)
        name = to_name(name)
        covers?(nsec, name) && in_zone?(nsec.next_domain, name) &&
          !(ancestor_delegation?(nsec) && in_zone?(name, nsec.name))
      end

      # RFC 4035 section 3.1.3.2 (name error): an NSEC covers qname, and
      # another covers the wildcard at the closest encloser. The encloser
      # is inferred from the covering NSEC: both its owner and its next
      # name exist, so the longest of their common ancestors with qname is
      # the closest encloser (RFC 4592 semantics). Neither cover may be
      # an empty non-terminal: a qname that is one exists (the answer
      # would be NOERROR), and a wildcard that is one exists too.
      def name_error(qname, nsecs)
        qname = to_name(qname)
        cover = nsecs.find { |rr| proves_absent?(rr, qname) }
        return nil unless cover

        ce = closest_encloser_from(cover, qname)
        wildcard = wildcard_of(ce)
        return nil unless nsecs.any? { |rr| proves_absent?(rr, wildcard) }

        Result.new(proof: :name_error, status: :secure, closest_encloser: ce)
      end

      # RFC 4035 sections 3.1.3.1/3.1.3.4 (no data): an NSEC matches qname
      # (directly, or at the wildcard that would have synthesized it) and
      # its bitmap has neither qtype nor CNAME - or an NSEC shows qname
      # to be an empty non-terminal, which has no types at all.
      def no_data(qname, qtype, nsecs)
        qname = to_name(qname)
        matching = nsecs.find { |rr| matches?(rr, qname) }
        if matching
          return nil if matching.types.include?(qtype) || matching.types.include?("CNAME")
          # The parent side of a delegation owns nothing at that name but DS.
          return nil if ancestor_delegation?(matching) && qtype != Dnsruby::Types.DS

          return Result.new(proof: :no_data, status: :secure)
        end

        if nsecs.any? { |rr| empty_non_terminal?(rr, qname) }
          return Result.new(proof: :no_data, status: :secure)
        end

        # Wildcard no data: qname itself is covered, and the wildcard at
        # the closest encloser exists but lacks the type.
        cover = nsecs.find { |rr| proves_absent?(rr, qname) }
        return nil unless cover

        ce = closest_encloser_from(cover, qname)
        wild = nsecs.find { |rr| matches?(rr, wildcard_of(ce)) }
        return nil unless wild
        return nil if wild.types.include?(qtype) || wild.types.include?("CNAME")

        Result.new(proof: :wildcard_no_data, status: :secure, closest_encloser: ce)
      end

      # RFC 4035 section 5.3.4 (wildcard answer): the RRSIG's Labels field
      # names the wildcard's parent; an NSEC must cover the next-closer
      # name, proving nothing more specific than the wildcard exists.
      def wildcard_answer(qname, rrsig_labels, nsecs)
        qname = to_name(qname)
        return nil if rrsig_labels >= qname.labels.length

        next_closer = Dnsruby::Name.new(qname.labels.last(rrsig_labels + 1), true)
        return nil unless nsecs.any? { |rr| proves_absent?(rr, next_closer) }

        Result.new(proof: :wildcard_answer, status: :secure)
      end

      # An NSEC proving +name+ is an unsigned delegation: NS set, DS and
      # SOA clear (RFC 4035 section 5.2). The insecure-delegation signal
      # for chain-of-trust walking.
      def insecure_delegation?(name, nsecs)
        matching = nsecs.find { |rr| matches?(rr, name) }
        !!matching && matching.types.include?("NS") &&
          !matching.types.include?("DS") && !matching.types.include?("SOA")
      end

      def to_name(name)
        name.is_a?(Dnsruby::Name) ? name : Dnsruby::Name.create(name)
      end

      # "*.<name>", built from labels so the root needs no special case.
      def wildcard_of(name)
        Dnsruby::Name.new([ Dnsruby::Name::Label.new("*") ] + name.labels, true)
      end

      def in_zone?(name, apex)
        apex_labels = apex.labels.map { |label| label.to_s.downcase }
        name_labels = name.labels.map { |label| label.to_s.downcase }
        name_labels.length >= apex_labels.length && name_labels.last(apex_labels.length) == apex_labels
      end

      def closest_encloser_from(nsec, qname)
        owner_ce = common_ancestor(nsec.name, qname)
        next_ce = common_ancestor(nsec.next_domain, qname)
        owner_ce.labels.length >= next_ce.labels.length ? owner_ce : next_ce
      end

      def common_ancestor(a, b)
        a_labels = a.labels.map { |label| label.to_s.downcase }.reverse
        b_labels = b.labels.map { |label| label.to_s.downcase }.reverse
        shared = a_labels.zip(b_labels).take_while { |x, y| x == y }.length
        Dnsruby::Name.new(a.labels.last(shared), true)
      end
    end
  end
end
