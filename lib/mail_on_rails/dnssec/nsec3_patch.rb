# frozen_string_literal: true

# Hashed-name matching for Dnsruby::RR::NSEC3 (RFC 5155 section 8.2).
#
# Upstream ships the codec and the section 5 hash (NSEC3.calculate_hash)
# but leaves check_name_in_range as a stub, so no NSEC3 can ever match or
# cover a name. These methods supply the missing comparisons; the proofs
# built on them live in Dnsruby::Nsec3Proof.
module Dnsruby
  class RR
    class NSEC3
      # RFC 9276 section 3.2: a validator SHOULD treat responses whose
      # NSEC3 iteration count exceeds 100 as insecure rather than spend
      # the CPU (an attacker-amplifiable cost) validating them.
      MAX_PROOF_ITERATIONS = 100

      # decode_rdata leaves an absent salt as [] (get_bytes is never
      # called for length 0), but hashing concatenates the salt onto a
      # String; wire-decoded zero-salt records (com, net, ...) need this.
      def raw_salt
        @salt.is_a?(String) ? @salt : ""
      end

      # The owner's first label: the base32hex hash this record is about.
      def hashed_owner_label
        name.labels[0].to_s.downcase
      end

      # The zone this record can prove facts about: owner minus the hash
      # label.
      def nsec3_zone
        Name.new(name.labels[1..], true)
      end

      def usable_for_proofs?
        Nsec3HashAlgorithms.SHA_1 == hash_alg &&
          iterations <= MAX_PROOF_ITERATIONS &&
          name.labels.length >= 2
      end

      # Base32hex hash of +other_name+ under this record's parameters, or
      # nil when the record is unusable or the name lies outside its zone.
      def proof_hash(other_name)
        return nil unless usable_for_proofs?

        other_name = Name.create(other_name) unless other_name.is_a?(Name)
        return nil unless in_nsec3_zone?(other_name)

        NSEC3.calculate_hash(other_name, iterations, raw_salt, hash_alg)
      end

      # This record's owner hash is the hash of +other_name+: the name
      # exists, and the type bitmap enumerates its types.
      def matches?(other_name)
        proof_hash(other_name) == hashed_owner_label
      end

      # The hash of +other_name+ falls strictly between this owner hash
      # and next_hashed: the name does not exist (or, under Opt-Out, has
      # no signed records). The chain is circular - the last record wraps
      # to the first, and owner == next is a single-record chain covering
      # everything but itself. base32hex was designed to preserve the sort
      # order of the raw digests, so string comparison suffices.
      def covers?(other_name)
        h = proof_hash(other_name)
        return false unless h

        owner = hashed_owner_label
        succ = NSEC3.encode_next_hashed(next_hashed)
        if owner < succ
          owner < h && h < succ
        else
          h > owner || h < succ
        end
      end

      # Upstream's stub returned false; give SingleVerifier's generic
      # NSEC(3) plumbing the real answer.
      def check_name_in_range(name)
        covers?(name)
      end

      # RFC 6840 section 4.4 applied to NSEC3: a record for a delegation
      # point (NS without SOA) or a DNAME proves nothing about names below
      # it - the child zone is authoritative there. Such a record must not
      # act as a closest encloser or prove no-data for anything but DS.
      def ancestor_delegation?
        (types.include?("NS") && !types.include?("SOA")) || types.include?("DNAME")
      end

      private

      def in_nsec3_zone?(other_name)
        zone_labels = name.labels[1..].map { |label| label.to_s.downcase }
        other_labels = other_name.labels.map { |label| label.to_s.downcase }
        other_labels.length >= zone_labels.length && other_labels.last(zone_labels.length) == zone_labels
      end
    end
  end
end
