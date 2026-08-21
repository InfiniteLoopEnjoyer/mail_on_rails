# frozen_string_literal: true

require "mail_on_rails/settings"
require "mail_on_rails/smtp/clamav_client"

module MailOnRails
  # App-side face of the one clamd client (Smtp::ClamavClient speaks the
  # INSTREAM protocol; this module just fronts it for the mailroom rescan,
  # the IMAP APPEND path, and the background scan jobs). One enablement
  # rule everywhere: smtp_clamav_addr empty means scanning is off, at the
  # SMTP edge and here alike - no path invents its own default address, so
  # "MX accepts mail" and "a scanner exists" can never disagree. Deploys
  # point it at the clamav accessory explicitly (deploy.yml sets
  # SMTP_CLAMAV_ADDR); Settings::Check warns when a production host runs
  # without one. In development the clamav_dev Puma plugin repoints it at
  # a local container (or "" when docker is unavailable); the test suite
  # pins "". Read per call: no Ractors here, and tests can toggle it.
  module ClamavScanner
    Result = Smtp::ClamavClient::Result

    module_function

    def enabled?
      Smtp::ClamavClient.enabled?
    end

    def addr
      Settings[:smtp_clamav_addr].to_s
    end

    def scan(raw)
      Smtp::ClamavClient.new.scan(raw)
    end
  end
end
