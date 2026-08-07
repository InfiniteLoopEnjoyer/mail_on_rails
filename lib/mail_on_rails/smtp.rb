# frozen_string_literal: true

# The in-process SMTP server (vendored from the former mail_on_rails_smtp
# gem): an SMTP server (RFC 5321 subset) with its own listener scaffolding,
# TLS, and SPF/DKIM/DMARC verification. Persistence goes through any object
# satisfying the SMTP store contract (MailOnRails::Smtp::Store::Contracts) -
# in this app, the ActiveRecord-backed MailOnRails::Store::SmtpBackend.
require_relative "smtp/version"
require_relative "smtp/server"
require_relative "smtp/session_helpers"
require_relative "smtp/sender_auth"
require_relative "smtp/clamav_client"
require_relative "smtp_server"
