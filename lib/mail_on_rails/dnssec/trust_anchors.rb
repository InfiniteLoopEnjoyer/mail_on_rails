# frozen_string_literal: true

module MailOnRails
  module Dnssec
    # The DNSSEC root trust anchors, as published in IANA's
    # root-anchors.xml (https://data.iana.org/root-anchors/). Both
    # currently-valid KSKs are included: KSK-2017 (tag 20326), signing
    # today, and KSK-2024 (tag 38696), scheduled to take over signing in
    # late 2026 - carrying both means the rollover needs no code change.
    #
    # Verify against the source when updating:
    #   curl https://data.iana.org/root-anchors/root-anchors.xml
    module TrustAnchors
      ROOT_DS = [
        ". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        ". 172800 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
      ].freeze

      module_function

      def root
        ROOT_DS.map { |line| Dnsruby::RR.create(line) }
      end

      # Anchors keyed the way Resolver consumes them: zone name => DS
      # records. Extra entries (a test root, a private zone's anchor)
      # merge over the default.
      def default
        { "." => root }
      end
    end
  end
end
