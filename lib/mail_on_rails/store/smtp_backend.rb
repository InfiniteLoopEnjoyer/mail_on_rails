# frozen_string_literal: true

require "mail_on_rails/store"

module MailOnRails
  module Store
    # The Active Record implementation of the SMTP store contract
    # (lib/mail_on_rails/smtp/store/contracts.rb), used by the in-process
    # SMTP server. Three responsibilities:
    #
    #   - authenticate: shared plumbing from Store::Base, defaulting
    #     source: "smtp" so AUTH attempts land in AuthAttempt and the
    #     shared AuthThrottle budget.
    #   - local_rcpts: RCPT-time recipient verification straight from the
    #     EmailAccount/EmailAlias/Domain tables (what the retired edge
    #     answered from the app-written local_recipients/local_domains
    #     files).
    #   - smtp_store/quarantine: accepted mail. Authenticated submission to
    #     remote recipients rows into SmtpOutboundMessage (drained by
    #     DeliverSmtpOutboundJob); local inbound becomes an
    #     ActionMailbox::InboundEmail routed to MailroomMailbox, with the
    #     connection facts the mailroom trusts stamped as headers first -
    #     exactly the contract the retired HTTP edge's ingress helper
    #     honored. Infected/unscanned mail is filed into Quarantine
    #     mailboxes directly at the model layer.
    #
    # The mailroom's trust boundary is unchanged: it believes the
    # connection-fact headers (Return-Path / X-Original-To /
    # X-MailOnRails-Authenticated / -Client-Ip / -Helo) because the edge -
    # now this process - stripped any wire copies before stamping its own,
    # and it recomputes every *verdict* (rspamd, clamav) itself. The SMTP
    # server's own SPF/DKIM/DMARC results stay a connection-time gate and
    # are deliberately not forwarded as headers.
    class SmtpBackend < Base
      # Headers a remote sender must not be able to forge: stripped from
      # the submitted DATA before we stamp authoritative values from the
      # SMTP session.
      TRUSTED_HEADERS = /\A(X-Original-To|X-MailOnRails-[\w-]+|Return-Path):/i

      def authenticate(email, password, ip: nil, source: "smtp")
        super
      end

      def record_auth_failure(email, ip: nil, source: "smtp")
        super
      end

      # local: hosted addresses (accounts and aliases), normalized.
      # unknown_in_local_domain: no such user, but the domain is one we
      # host - the session answers 5.1.1 instead of "relaying denied".
      def local_rcpts(addresses)
        db do
          normalized = Array(addresses).map { |a| a.to_s.strip.downcase }.reject(&:empty?).uniq
          local = normalized.select { |a| hosted_address?(a) }
          unknown = (normalized - local).select do |address|
            (domain = address.split("@").last) && hosted_domain?(domain)
          end
          { local: local, unknown_in_local_domain: unknown }
        end
      end

      def smtp_store(mail_from, rcpt_to, data, authenticated_as, client_ip: nil, helo: nil,
                     auth_results: nil, scan_status: nil)
        db do
          local, remote = partition_recipients(rcpt_to)
          next { error: "relay denied", code: :relay_denied } if remote.any? && !authenticated_as

          if remote.any? && SmtpOutboundMessage.pending.count + remote.size > outbound_limit
            next { error: "outbound queue full", code: :insufficient_storage }
          end

          inbound_id = nil
          if local.any?
            stamped = stamp(data, mail_from: mail_from, rcpt_to: local,
                            authenticated_as: authenticated_as, client_ip: client_ip, helo: helo)
            inbound_id = ActionMailbox::InboundEmail.create_and_extract_message_id!(stamped).id
          end
          SmtpOutboundMessage.transaction do
            remote.each do |recipient|
              SmtpOutboundMessage.create!(mail_from: authenticated_as, recipient: recipient,
                                          data: data, next_attempt_at: Time.current)
            end
          end
          { id: inbound_id || "outbound", outbound: remote.size }
        end
      end

      # Best-effort review copy of infected/unscanned mail, filed straight
      # into the Quarantine mailbox of every local recipient account (or
      # the submitter's own on an authenticated remote-only submission).
      # Deduped by Message-ID like MailroomMailbox#quarantine - a sending
      # MTA retries a 451 with the same message for days. The SMTP reply
      # was already decided from the scan verdict, so this records and
      # never fails the caller.
      def quarantine(mail_from, rcpt_to, data, authenticated_as, client_ip: nil, helo: nil,
                     auth_results:, scan_status:, virus: nil)
        result = db do
          local, = partition_recipients(rcpt_to)
          accounts = local.filter_map { |address| resolve_account(address) }.uniq
          if accounts.empty? && authenticated_as
            accounts = [ resolve_account(authenticated_as.to_s.strip.downcase) ].compact
          end
          if accounts.empty?
            log(:warn, "quarantine copy dropped: no local target (#{scan_status})")
            next nil
          end

          stamped = stamp(data, mail_from: mail_from, rcpt_to: local,
                          authenticated_as: authenticated_as, client_ip: client_ip, helo: helo)
          # Angle brackets stripped to match what deliver_raw stores
          # (Mail#message_id is bracketless).
          mid = stamped[/^Message-ID:[ \t]*<([^>]*)>/i, 1].to_s.presence
          accounts.each do |account|
            mailbox = account.quarantine_mailbox
            if mid && mailbox.email_messages.exists?(message_id: mid)
              log(:info, "skipped duplicate quarantine copy for #{account.email} (#{mid})")
              next
            end

            EmailMessage.deliver_raw(mailbox, stamped,
                                     authenticated_as: authenticated_as.to_s.strip.presence,
                                     auth_results: auth_results, scan_status: scan_status, virus_name: virus)
            log(:warn, "quarantined #{scan_status} message for #{account.email}#{" (#{virus})" if virus}")
          end
          nil
        end
        # db turns store errors into an error hash; quarantine's contract
        # is "record if you can, never fail the caller" - flatten to nil.
        result.is_a?(Hash) && result[:error] ? nil : result
      end

      private

      def hosted_address?(address)
        EmailAccount.exists?(email: address) || EmailAlias.exists?(email: address)
      end

      # A domain counts as ours when it has a Domain row (the managed set)
      # or when any account/alias lives under it - so "no such user here"
      # stays accurate even for a domain that predates its Domain row.
      def hosted_domain?(domain)
        pattern = "%@#{ActiveRecord::Base.sanitize_sql_like(domain)}"
        Domain.exists?(name: domain) ||
          EmailAccount.where(EmailAccount.arel_table[:email].matches(pattern)).exists? ||
          EmailAlias.where(EmailAlias.arel_table[:email].matches(pattern)).exists?
      end

      def resolve_account(address)
        EmailAccount.find_by(email: address) || EmailAlias.find_by(email: address)&.email_account
      end

      def partition_recipients(rcpt_to)
        Array(rcpt_to).map { |a| a.to_s.strip.downcase }.reject(&:empty?).uniq
                      .partition { |a| hosted_address?(a) }
      end

      # Bounds the outbound queue (authenticated senders only, but still).
      def outbound_limit
        Integer(ENV.fetch("MAIL_ON_RAILS_OUTBOUND_LIMIT", 1_000))
      end

      # The message source with the authoritative trust/routing headers
      # prepended (forged copies stripped): envelope recipients become
      # X-Original-To so mailroom routing sees BCC'd and aliased
      # recipients, Return-Path records the envelope sender,
      # X-MailOnRails-Authenticated whether the sender authenticated (and
      # as whom), and X-MailOnRails-Client-Ip/-Helo the connection facts
      # the mailroom feeds to rspamd.
      def stamp(data, mail_from:, rcpt_to:, authenticated_as:, client_ip:, helo:)
        authenticated = authenticated_as.to_s.strip
        stamped = [ "Return-Path: <#{sanitize_header(mail_from)}>\r\n" ]
        stamped += Array(rcpt_to).map { |rcpt| "X-Original-To: #{sanitize_header(rcpt)}\r\n" }
        stamped << "X-MailOnRails-Authenticated: #{authenticated.empty? ? "no" : sanitize_header(authenticated)}\r\n"
        stamped << "X-MailOnRails-Client-Ip: #{sanitize_header(client_ip)}\r\n" unless client_ip.to_s.strip.empty?
        stamped << "X-MailOnRails-Helo: #{sanitize_header(helo)}\r\n" unless helo.to_s.strip.empty?
        stamped.join + strip_trusted_headers(data)
      end

      # Drops CR/LF so an envelope value can't inject extra header lines.
      def sanitize_header(value)
        value.to_s.gsub(/[\r\n]/, " ")
      end

      def strip_trusted_headers(raw)
        header_block, separator, body = raw.to_s.partition(/\r?\n\r?\n/)
        kept = header_block.split(/\r?\n(?![ \t])/).reject { |line| line.match?(TRUSTED_HEADERS) }
        kept.join("\r\n") + separator + body
      end
    end
  end
end
