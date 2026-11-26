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
#
# The second loop needs no failure at all. Our report to a large
# receiver is itself mail from our report domain, so that receiver's
# next report to us covers it; that report is mail from the receiver's
# domain arriving at our dmarc@ mailbox, so we record an event for it and
# report on it the following night - one report each way, daily, with no
# real mail anywhere in the exchange. TLS-RPT closes the same circle on
# its own: delivering a report is a TLS session with the destination,
# which would earn the destination tomorrow's report. Two more cuts: the
# edge records no DMARC event for mail addressed only to our report
# mailboxes (for_report_mailboxes?), and the deliverer records no TLS-RPT
# event for a session that carried one of our reports (OutboundDeliverer).
module MailOnRails
  module AggregateReport
    KINDS = %w[dmarc tlsrpt].freeze

    # Message-ID of every report we send, distinctive enough to spot inside
    # whatever a remote MTA wraps around it when bouncing it back - the
    # In-Reply-To of an Exchange NDR, the embedded original of a Postfix
    # bounce: <dmarc-report.<report id>@<submitter>>.
    MESSAGE_ID_PATTERN = /<(?:#{KINDS.join("|")})-report\.[^\s<>@]{1,200}@[^\s<>@]{1,253}>/i

    # Local parts of the accounts every hosted domain receives reports at
    # and sends its own from: Domain::DMARC_LOCAL_PART and
    # Domain::TLS_RPT_LOCAL_PART, repeated because this module loads
    # without Rails (a test holds the two in step).
    MAILBOX_LOCAL_PARTS = %w[dmarc tls-rpt].freeze

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

    # Is every recipient a dmarc@ / tls-rpt@ report mailbox? The caller is
    # the MX edge, whose accepted recipients are all at hosted domains, so
    # the local part settles it. Mail like that is another receiver's
    # report (or someone imitating one), not traffic its From domain needs
    # a report about; a message that also names a person's mailbox is
    # ordinary mail and is reported as usual. Imitating a report only
    # keeps the imitated domain from hearing about one message nobody
    # read.
    def self.for_report_mailboxes?(recipients)
      recipients = Array(recipients)
      recipients.any? && recipients.all? do |recipient|
        local, at, domain = recipient.to_s.strip.downcase.rpartition("@")
        !at.empty? && !domain.empty? && MAILBOX_LOCAL_PARTS.include?(local)
      end
    end
  end
end
