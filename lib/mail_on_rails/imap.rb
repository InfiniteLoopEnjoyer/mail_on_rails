# frozen_string_literal: true

# The in-process IMAP server (vendored from the former mail_on_rails_imap
# gem): an IMAP4rev1 server (RFC 3501 subset) with its own listener
# scaffolding, TLS, and MIME handling. Persistence goes through any object
# satisfying the IMAP store contract (MailOnRails::Imap::Store::Contracts) -
# in this app, the ActiveRecord-backed MailOnRails::Store::ImapBackend.
require_relative "imap/version"
require_relative "imap/server"
require_relative "imap_server"
