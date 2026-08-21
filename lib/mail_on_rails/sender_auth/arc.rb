# frozen_string_literal: true

require_relative "dkim"

module MailOnRails
  module SenderAuth
    # ARC chain validator (RFC 8617): the receiving half of the story
    # whose sealing half is MailOnRails::ArcSealer. A forwarder that
    # breaks SPF (new envelope) or DKIM (rewritten body) attaches an ARC
    # set vouching for the authentication results it saw on arrival; an
    # intact chain from a sealer the operator trusts is grounds to
    # override a DMARC reject (the smtp_arc_trusted_sealers setting).
    #
    # One chain verdict per message:
    #
    #   :none      - no ARC headers at all
    #   :pass      - structurally complete chain, every ARC-Seal verifies,
    #                the newest ARC-Message-Signature verifies, and every
    #                cv= is honest (none at i=1, pass above)
    #   :fail      - a signature or cv= that does not hold up
    #   :permerror - malformed/incomplete sets, or a chain longer than
    #                MAX_INSTANCES
    #   :temperror - a DNS key lookup failed transiently
    #
    # Subclasses the DKIM verifier for its RFC 6376 machinery (tag
    # parsing, canonicalization, key retrieval) - ARC borrows all of it.
    class Arc < Dkim
      # RFC 8617 allows 50; nothing legitimate approaches that, and each
      # instance costs a DNS lookup plus a signature check, so cap the
      # work a hostile message can demand.
      MAX_INSTANCES = 10

      def evaluate(raw)
        @seal_tags = {}
        raw = raw.to_s.gsub(/(?<!\r)\n/, "\r\n")
        header_block, _, body = raw.partition("\r\n\r\n")
        headers = header_block.split(/\r\n(?![ \t])/)

        sets, structure_error = collect_sets(headers)
        return { result: :none } if sets.empty? && structure_error.nil?
        return { result: :permerror, detail: structure_error } if structure_error

        n = sets.keys.max
        sealers = (1..n).map { |i| seal_tags(headers, sets, i)["d"].to_s.downcase }

        # cv= honesty first (RFC 8617 5.2 step 2): the first seal attests
        # to no prior chain, every later one to a chain it validated.
        (1..n).each do |i|
          expected = i == 1 ? "none" : "pass"
          cv = seal_tags(headers, sets, i)["cv"].to_s.downcase
          unless cv == expected
            return { result: :fail, sealer: sealers.last, sealers: sealers,
                     detail: "ARC-Seal i=#{i} cv=#{cv.empty? ? "(missing)" : cv}" }
          end
        end

        # The newest AMS is the only one that must still verify - older
        # ones are expected to be broken by later forwarding hops.
        ams = verify_ams(headers, sets[n][:ams], body, n)
        unless ams[:result] == :pass
          failure = ams[:result] == :temperror ? :temperror : :fail
          return { result: failure, sealer: sealers.last, sealers: sealers,
                   detail: "ARC-Message-Signature i=#{n}: #{ams[:detail]}" }
        end

        # Every seal must verify - each one signs the whole chain so far,
        # so one bad link invalidates everything after it.
        (1..n).each do |i|
          seal = verify_seal(headers, sets, i)
          unless seal[:result] == :pass
            failure = seal[:result] == :temperror ? :temperror : :fail
            return { result: failure, sealer: sealers.last, sealers: sealers,
                     detail: "ARC-Seal i=#{i}: #{seal[:detail]}" }
          end
        end

        { result: :pass, sealer: sealers.last, sealers: sealers }
      rescue StandardError => e
        { result: :permerror, detail: "#{e.class}: #{e.message}" }
      end

      private

      # Groups the ARC headers by instance: {i => {aar:, ams:, as: index}}.
      # Returns [sets, error]; any structural defect (missing member,
      # duplicate, gap, over-length chain) is terminal per RFC 8617 5.2.
      def collect_sets(headers)
        sets = Hash.new { |h, k| h[k] = {} }
        headers.each_index do |index|
          role = { "arc-authentication-results" => :aar,
                   "arc-message-signature" => :ams,
                   "arc-seal" => :as }[header_name(headers[index]).downcase]
          next unless role

          instance = arc_instance(headers[index], role)
          return [ {}, "unparseable i= on #{header_name(headers[index])}" ] unless instance
          return [ {}, "chain longer than #{MAX_INSTANCES} sets" ] if instance > MAX_INSTANCES
          return [ {}, "duplicate #{header_name(headers[index])} i=#{instance}" ] if sets[instance][role]

          sets[instance][role] = index
        end
        return [ {}, nil ] if sets.empty?

        n = sets.keys.max
        unless sets.keys.sort == (1..n).to_a && sets.values.all? { |set| set[:aar] && set[:ams] && set[:as] }
          return [ {}, "incomplete ARC set" ]
        end

        [ sets, nil ]
      end

      # AAR carries its instance as a leading "i=N;" clause; AMS and AS
      # as an ordinary i= tag.
      def arc_instance(header, role)
        value = header.split(":", 2).last.to_s
        raw = role == :aar ? value[/\A[\s]*i[ \t]*=[ \t]*(\d{1,3})[ \t]*;/m, 1] : parse_tags(value)["i"]
        instance = raw.to_s[/\A\d{1,3}\z/]&.to_i
        instance&.positive? ? instance : nil
      end

      def seal_tags(headers, sets, instance)
        @seal_tags[instance] ||= parse_tags(headers[sets[instance][:as]].split(":", 2).last)
      end

      # -- ARC-Message-Signature -------------------------------------------
      #
      # A DKIM signature in all but name; verified with the inherited
      # machinery, but under ARC's tag rules: no v=, i= is the instance
      # (never an AUID), and From: need not be covered.
      def verify_ams(headers, index, body, instance)
        tags = parse_tags(headers[index].split(":", 2).last)
        begin
          validate_ams_tags(tags, instance)
          digest, key_type = algorithm(tags["a"])
          header_canon, body_canon = (tags["c"] || "simple/simple").downcase.split("/", 2)
          body_canon ||= "simple"

          canonical_body = canonicalize_body(body, body_canon)
          bh = [ digest.digest(canonical_body) ].pack("m0")
          return { result: :fail, detail: "body hash mismatch" } unless bh == tags["bh"].gsub(/\s/, "")

          data = signed_header_data(headers, index, tags["h"], header_canon)
          key = public_key(tags.except("i"), key_type, digest)
          signature = decode64(tags["b"], "b")

          verified =
            if key_type == "ed25519"
              key.verify(nil, signature, digest.digest(data))
            else
              key.verify(digest.new, signature, data)
            end
          verified ? { result: :pass } : { result: :fail, detail: "signature mismatch" }
        rescue Unusable => e
          { result: :fail, detail: e.message }
        rescue Dns::TempError
          { result: :temperror, detail: "DNS failure fetching key" }
        rescue OpenSSL::PKey::PKeyError, OpenSSL::OpenSSLError => e
          { result: :fail, detail: "key error: #{e.class}" }
        end
      end

      def validate_ams_tags(tags, instance)
        %w[a b bh d h s i].each do |required|
          raise Unusable, "missing #{required}= tag" if tags[required].to_s.empty?
        end
        raise Unusable, "i= mismatch" unless tags["i"].to_i == instance
        # Same stance as the DKIM verifier: l= leaves a tail unsigned.
        raise Unusable, "l= body truncation not accepted" if tags["l"]
        # RFC 8617 4.1.2: an AMS covering ARC-Seal headers cannot verify
        # once later seals are added - reject the construction.
        if tags["h"].downcase.split(":").map(&:strip).any? { |name| name.start_with?("arc-seal") }
          raise Unusable, "h= covers ARC-Seal"
        end
        if tags["x"] && tags["x"] =~ /\A\d+\z/ && Time.now.to_i > tags["x"].to_i
          raise Unusable, "signature expired"
        end
      end

      # -- ARC-Seal ----------------------------------------------------------
      #
      # AS(i) signs, relaxed-canonicalized, in increasing instance order:
      # AAR(k), AMS(k), AS(k) for k = 1..i, with its own b= emptied and
      # no trailing CRLF (RFC 8617 5.1.1).
      def verify_seal(headers, sets, instance)
        tags = seal_tags(headers, sets, instance)
        %w[a b cv d s].each do |required|
          return { result: :fail, detail: "missing #{required}= tag" } if tags[required].to_s.empty?
        end

        digest, key_type = algorithm(tags["a"])
        scope = (1..instance).flat_map do |k|
          [ :aar, :ams, :as ].map do |role|
            header = headers[sets[k][role]]
            if role == :as && k == instance
              header = header.sub(/(\A|;)([\s]*b[ \t]*=)[^;]*/m, '\1\2')
            end
            canonicalize_header(header, "relaxed")
          end
        end
        data = scope.join.chomp("\r\n")

        key = public_key(tags.except("i"), key_type, digest)
        signature = decode64(tags["b"], "b")
        if key_type == "ed25519" ? key.verify(nil, signature, digest.digest(data)) : key.verify(digest.new, signature, data)
          { result: :pass }
        else
          { result: :fail, detail: "seal signature mismatch" }
        end
      rescue Unusable => e
        { result: :fail, detail: e.message }
      rescue Dns::TempError
        { result: :temperror, detail: "DNS failure fetching key" }
      rescue OpenSSL::PKey::PKeyError, OpenSSL::OpenSSLError => e
        { result: :fail, detail: "key error: #{e.class}" }
      end
    end
  end
end
