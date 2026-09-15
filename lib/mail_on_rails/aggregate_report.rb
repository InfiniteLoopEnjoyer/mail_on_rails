# frozen_string_literal: true

# What the DMARC (RFC 7489) and TLS-RPT (RFC 8460) aggregate reports this
# server sends have in common, shared between the jobs that build them
# (SendDmarcReportsJob / SendTlsRptReportsJob, core) and the SMTP edge
# that has to recognise them coming back (mail_on_rails_smtp) - so a
# plain module under lib, loadable without Rails.
#
# The feedback loop that made this necessary: a report to a domain whose
# rua mailbox rejects it (full, nonexistent, our IP on a blocklist) comes
# back as a DSN from that domain's postmaster. The DSN is an ordinary
# inbound message from a domain that publishes DMARC, so the edge records
# an aggregate event for it, the next night's job sends the domain a
# report saying "we got one message from your postmaster", that bounces,
# and so on daily, forever. Two cuts break it: the edge does not record
# events for null-sender mail that references one of our report
# Message-IDs (this module), and a rua address that hard-bounced is
# skipped for a cooldown (AggregateReportJob).
module MailOnRails
  module AggregateReport
    KINDS = %w[dmarc tlsrpt].freeze

    # Message-ID of every report we send, distinctive enough to spot inside
    # whatever a remote MTA wraps around it when bouncing it back - the
    # In-Reply-To of an Exchange NDR, the embedded original of a Postfix
    # bounce: <dmarc-report.<report id>@<submitter>>.
    MESSAGE_ID_PATTERN = /<(?:#{KINDS.join("|")})-report\.[^\s<>@]{1,200}@[^\s<>@]{1,253}>/i

    # A DSN quotes the original's headers near its end; reports themselves
    # are a few KB, so the reference is always well inside this.
    SCAN_LIMIT = 256 * 1024

    def self.message_id(kind, report_id, submitter)
      raise ArgumentError, "unknown report kind #{kind.inspect}" unless KINDS.include?(kind.to_s)

      "<#{kind}-report.#{report_id}@#{submitter}>"
    end

    # Does this raw message mention one of our report Message-IDs? Only
    # meaningful for null-sender (MAIL FROM:<>) mail, i.e. a DSN: that is
    # the one shape our own reports come back in. Forgeable, but forging
    # it only spares the forger's own domain a report about itself.
    def self.references?(data)
      data.to_s.b[0, SCAN_LIMIT].to_s.match?(MESSAGE_ID_PATTERN)
    end
  end
end
