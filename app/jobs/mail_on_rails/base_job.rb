# frozen_string_literal: true

module MailOnRails
  # Base class for the gem's jobs. The host app supplies the Active Job
  # queue adapter; retry/discard policy can be added via the load hook.
  class BaseJob < ActiveJob::Base
    private

    # True when an inbound report (fbl@/dmarc@/tls-rpt@) may be acted on:
    # its From: domain must be DMARC-aligned (so it isn't spoofed) AND
    # appear on report_reporter_allowlist. Anyone can pass DMARC for their
    # own domain, so a bare DMARC pass is not proof of a real reporter -
    # the allowlist names which domains we believe (audit H1). Suffix
    # match, so "google.com" also trusts "noreply.google.com". Reason is
    # returned for the caller's log line; nil means trusted.
    def report_reporter_untrusted_reason(email_message)
      return "report itself did not pass DMARC" unless email_message.auth_result("dmarc") == "pass"

      domain = email_message.from_address.to_s.split("@").last.to_s.downcase.strip
      return "no From: domain" if domain.empty?

      allowlist = MailOnRails::Settings[:report_reporter_allowlist]
      trusted = allowlist.any? do |entry|
        entry = entry.to_s.downcase.strip.delete_prefix("@")
        entry.present? && (domain == entry || domain.end_with?(".#{entry}"))
      end
      trusted ? nil : "#{domain} is not on report_reporter_allowlist"
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_base_job, MailOnRails::BaseJob
