# frozen_string_literal: true

require_relative "lib/mail_on_rails/version"

Gem::Specification.new do |spec|
  spec.name = "mail_on_rails"
  spec.version = MailOnRails::VERSION
  spec.summary = "A complete mail server for Rails: SMTP + IMAP, database-backed"
  spec.description = "In-process SMTP (RFC 5321 subset, SPF/DKIM/DMARC/ARC) and " \
                     "IMAP4rev1 (RFC 3501 subset, CONDSTORE/QRESYNC) servers that " \
                     "store mail in your app's database (PostgreSQL, MySQL, or " \
                     "SQLite). The gem owns the " \
                     "models and migrations; the servers run standalone via " \
                     "bin/mail_server or inside the web process as a Puma plugin. " \
                     "Includes outbound delivery (MX, DANE, MTA-STS), DKIM key " \
                     "management, and DMARC/TLS-RPT report handling."
  spec.authors = [ "Tayden Miller" ]
  spec.homepage = "https://github.com/InfiniteLoopEnjoyer/mail_on_rails"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.4"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage
  }

  spec.files = Dir["{app,config,db,exe,lib}/**/*", "docs/store_contract.md", "MIT-LICENSE", "README.md"]
  spec.bindir = "exe"
  spec.executables = [ "mail_on_rails" ]
  spec.require_paths = [ "lib" ]

  # Individual Rails components, never the rails monolith. Action Mailbox is
  # a real dependency: inbound mail is ingested as ActionMailbox::InboundEmail
  # and processed by MailOnRails::MailroomMailbox.
  spec.add_dependency "activerecord", ">= 8.0"
  spec.add_dependency "activejob", ">= 8.0"
  spec.add_dependency "railties", ">= 8.0"
  spec.add_dependency "actionmailbox", ">= 8.0"

  # has_secure_password on MailOnRails::EmailAccount.
  spec.add_dependency "bcrypt"

  # The standalone CLI (bin/mail_server). Transitive via railties, but
  # MailOnRails::Cli requires it directly.
  spec.add_dependency "thor", ">= 1.3"

  # DKIM signing for outbound mail and ARC sealing (RFC 6376/8617).
  spec.add_dependency "dkim"

  # DMARC aggregate reports arrive as .zip attachments (RFC 7489); gzip and
  # plain XML are handled with the stdlib.
  spec.add_dependency "rubyzip"

  # XML parsing for the DMARC report ingester.
  spec.add_dependency "nokogiri"

  # EmailHtmlSanitizer: HTML5 parsing plus the CSS property safelist that
  # scrubs inline styles and stylesheet rules. crass (loofah's own CSS
  # tokenizer) is used directly by EmailCssSanitizer.
  spec.add_dependency "loofah"
  spec.add_dependency "crass"

  # Publishes DNS records for hosted domains (CloudflareDns/DnsPublisher).
  spec.add_dependency "cloudflare"

  # In-process DNSSEC validation (lib/mail_on_rails/dnssec): a validating
  # stub resolver built on dnsruby's codec and RRSIG verification, plus
  # our patches (NSEC3/NSEC denial proofs, Ed25519/Ed448, wildcard
  # verification) until they land upstream. The outbound DANE path
  # validates with this - no external resolver is trusted.
  spec.add_dependency "dnsruby", ">= 1.74"

  # The ICANN Public Suffix List, for DMARC organizational-domain
  # computation (relaxed alignment, aggregate-report grouping). Loaded
  # lazily by Smtp::SenderAuth::Dmarc with a two-label fallback, so the
  # protocol tree still runs without it.
  spec.add_dependency "public_suffix"

  # IDNA/punycode conversion for internationalized domains (SMTPUTF8
  # envelopes, RFC 6531): DNS wants A-labels, the wire may carry U-labels.
  # Loaded lazily with graceful degradation, like public_suffix.
  spec.add_dependency "simpleidn"

  # logger stopped being a default gem in Ruby 4.0, so `require "logger"`
  # (daemons, netserv) raises LoadError under bundler unless declared.
  spec.add_dependency "logger"

  # The json default gem shipped with ruby 4.0.6 (2.18.0) carries
  # CVE-2026-33210; the fixed floor has to be declared here so standalone
  # (non-Rails-app) processes resolve a safe version.
  spec.add_dependency "json", ">= 2.19.2"
end
