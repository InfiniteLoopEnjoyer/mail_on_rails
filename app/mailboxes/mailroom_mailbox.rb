require "mail_on_rails/clamav_scanner"
require "mail_on_rails/rspamd_analyzer"

# Delivers inbound mail into the INBOX of every local account that appears
# as a recipient (To/Cc/Bcc or the X-Original-To envelope headers stamped
# by the in-process SMTP server via Store::SmtpBackend#stamp).
#
# Trust boundary: the SMTP edge stamps the connection facts it alone can
# know - Return-Path, X-Original-To, X-MailOnRails-Authenticated / -Client-Ip
# / -Helo - after stripping any forged copies from the submitted DATA, and
# this mailroom trusts those (it can't re-derive them; it never saw the
# wire). It does NOT trust any inbound *verdict* header
# (X-MailOnRails-Auth-Results / -Scan / -Virus): the edge never produces
# those, so a copy arriving on the wire could only be forged and must not
# be allowed to skip our checks. The mailroom recomputes both verdicts
# itself, unconditionally:
#   - Sender-auth (SPF/DKIM/DMARC) via rspamd from the stamped connection
#     facts, when SMTP_RSPAMD_ADDR is set;
#   - Virus scanning via clamav, on by default (SMTP_CLAMAV_ADDR defaults
#     to the clamav accessory; "" disables).
# Anything not clean is filed into the account's Quarantine mailbox for
# review instead of INBOX, deduped by Message-ID because a retrying sender
# re-sends the same message for days. Virus-clean mail that rspamd calls
# spam is filed into Junk instead of INBOX - as is, when
# MAILROOM_DMARC_ENFORCE=enforce, mail that failed DMARC under the sender
# domain's own p=reject/p=quarantine policy (log-only by default).
class MailroomMailbox < ApplicationMailbox
  def process
    verdict = scan_verdict
    # uniq: several recipient addresses (an account plus its aliases) can
    # resolve to the same account - it still gets exactly one copy.
    recipients.filter_map { |recipient| resolve_account(recipient.strip.downcase) }.uniq.each do |account|
      # A full account loses only its own copy - the message was already
      # accepted at the SMTP edge, so there is no rejecting it now, and
      # co-recipients must still get theirs.
      if verdict && verdict[:status] != "clean"
        quarantine(account, verdict)
      else
        # Virus-clean but rspamd says spam - or the sender domain's own
        # DMARC policy asks for rejection/quarantine and enforcement is on:
        # file into Junk, not INBOX.
        dest = sender_analysis&.spam? || dmarc_policy_junk? ? account.junk_mailbox : account.inbox
        message = EmailMessage.deliver_raw(dest, inbound_email.source,
                                           authenticated_as: authenticated_as, auth_results: auth_results,
                                           scan_status: verdict&.dig(:status), **spam_attributes)
        sweep_stale_unscanned(account)
        Rails.logger.info "[mail_on_rails] delivered inbound message to #{account.email} #{dest.name}"
        # Vacation auto-reply, only for mail that earned the INBOX: junk
        # and quarantine never get one (answering spam confirms a live
        # address). VacationResponder carries the loop protections.
        vacation_reply(account) if dest.inbox?
        # Mail to a domain's dmarc@ ingestion account carries aggregate
        # reports - parse them only after a real clamav scan came back
        # clean (on this branch a present verdict IS clean). Quarantined,
        # spam-filed and unscanned mail is never parsed: with scanning
        # disabled the report just stays in the mailbox.
        if dest.inbox? && Domain.dmarc_ingestion_address?(account.email)
          if verdict
            IngestDmarcReportJob.perform_later(message)
          else
            Rails.logger.warn "[mail_on_rails] dmarc report for #{account.email} left unparsed (virus scanning disabled)"
          end
        end
      end
    rescue EmailMessage::OverQuota => e
      Rails.logger.warn "[mail_on_rails] inbound message dropped for #{account.email}: #{e.message}"
    end
  end

  private

  # The auto-reply must never cost the sender their mail: a responder
  # bug is logged, not raised (raising would fail the routing job and
  # re-deliver the message).
  def vacation_reply(account)
    VacationResponder.deliver_if_due(account, mail, return_path: return_path)
  rescue StandardError => e
    Rails.logger.error "[mail_on_rails] vacation responder failed for #{account.email}: #{e.class}: #{e.message}"
  end

  # A recipient address is either an account's own address or one of its
  # aliases (the two sets are kept disjoint by model validations); both
  # deliver into the account's mailboxes.
  def resolve_account(address)
    EmailAccount.find_by(email: address) || EmailAlias.find_by(email: address)&.email_account
  end

  def recipients
    envelope = header_values("X-Original-To")
    (Array(mail.recipients) + envelope).map(&:to_s).uniq
  end

  # Read from the authoritative header stamped by the SMTP edge (any
  # forged copy in the submitted DATA was stripped there). "no" / absent
  # means the sender did not authenticate.
  def authenticated_as
    value = header_values("X-MailOnRails-Authenticated").first.to_s.strip
    value.presence unless value.casecmp?("no")
  end

  # SPF/DKIM/DMARC verdicts as an Authentication-Results string, computed by
  # the app via rspamd from the edge-stamped connection facts. Any inbound
  # X-MailOnRails-Auth-Results header is ignored - the edge never stamps one,
  # so it could only be forged. Nil for authenticated submissions (the sender
  # is already trusted) and when rspamd is off or unreachable.
  def auth_results
    sender_analysis&.auth_results
  end

  # The rspamd analysis for an inbound message - the single gate for every
  # rspamd-derived value (the sender-auth string and the spam verdict).
  # Skipped only for an authenticated local submitter (already trusted), so
  # rspamd never runs on that path. Memoized downstream via rspamd_analysis.
  def sender_analysis
    return if authenticated_as

    rspamd_analysis
  end

  # rspamd's spam verdict as EmailMessage columns, gated the same way as
  # sender-auth. Splatted into deliver_raw on both delivery paths.
  def spam_attributes
    { spam_score: sender_analysis&.score, spam_threshold: sender_analysis&.required_score,
      spam_action: sender_analysis&.action }
  end

  # Runs rspamd once per message (memoized - auth_results is read per
  # recipient) with the connection facts the edge forwarded. A verdict rspamd
  # can't produce (disabled or unreachable) leaves sender-auth blank rather
  # than holding up delivery; the spam action is logged for visibility.
  def rspamd_analysis
    return @rspamd_analysis if defined?(@rspamd_analysis)

    @rspamd_analysis =
      if MailOnRails::RspamdAnalyzer.enabled?
        result = MailOnRails::RspamdAnalyzer.analyze(
          inbound_email.source, ip: client_ip, helo: helo, mail_from: return_path, rcpt: recipients.first
        )
        if result.unavailable?
          Rails.logger.warn "[mail_on_rails] rspamd unavailable; delivering #{return_path} without sender-auth verdicts"
        else
          Rails.logger.info "[mail_on_rails] rspamd action=#{result.action} score=#{result.score} for #{return_path}"
        end
        result
      end
  end

  # App-layer DMARC enforcement, the second look after the SMTP edge's
  # SMTP_DMARC_ENFORCE (which can 550 a p=reject failure outright at DATA
  # time, before the message is ever accepted). rspamd sets dmarc_policy
  # only when the message failed DMARC under a published p=reject or
  # p=quarantine - a p=none failure carries no policy - so acting on it
  # always honors what the domain owner asked for. Post-acceptance there
  # is no rejecting without backscatter (the envelope sender of DMARC-fail
  # mail is exactly the address not to bounce to), so "enforce" files into
  # Junk for review. The default is log-only: watch the would-be filings
  # against real traffic before flipping it on. Memoized so multi-recipient
  # messages log once.
  def dmarc_policy_junk?
    return @dmarc_policy_junk if defined?(@dmarc_policy_junk)

    @dmarc_policy_junk = begin
      policy = sender_analysis&.dmarc_policy
      mode = ENV.fetch("MAILROOM_DMARC_ENFORCE", "log").to_s.strip.downcase
      if policy.nil? || %w[0 off].include?(mode)
        false
      elsif %w[1 enforce].include?(mode)
        Rails.logger.warn "[mail_on_rails] DMARC p=#{policy} failure from #{return_path}: filing into Junk"
        true
      else
        Rails.logger.warn "[mail_on_rails] DMARC p=#{policy} failure from #{return_path}: " \
                          "would file into Junk (MAILROOM_DMARC_ENFORCE=log)"
        false
      end
    end
  end

  def client_ip
    header_values("X-MailOnRails-Client-Ip").first.to_s.strip.presence
  end

  def helo
    header_values("X-MailOnRails-Helo").first.to_s.strip.presence
  end

  def return_path
    header_values("Return-Path").first.to_s.strip.delete("<>").presence
  end

  # The app's own clamav verdict; nil when scanning is disabled. An inbound
  # X-MailOnRails-Scan / -Virus header is never trusted (the edge doesn't
  # produce one), so every inbound message is scanned here.
  def scan_verdict
    return unless MailOnRails::ClamavScanner.enabled?

    result = MailOnRails::ClamavScanner.scan(inbound_email.source)
    # :unavailable degrades to a quarantined "unscanned" copy rather than
    # raising: a retrying routing job would delay every recipient, and the
    # flagged row keeps the message reviewable either way.
    { status: result.infected? ? "infected" : (result.clean? ? "clean" : "unscanned"),
      virus: result.virus }
  end

  def quarantine(account, verdict)
    mid = mail.message_id.to_s.presence
    mailbox = account.quarantine_mailbox
    if mid && mailbox.email_messages.exists?(message_id: mid)
      Rails.logger.info "[mail_on_rails] skipped duplicate quarantine copy for #{account.email} (#{mid})"
      return
    end

    EmailMessage.deliver_raw(mailbox, inbound_email.source,
                             authenticated_as: authenticated_as, auth_results: auth_results,
                             scan_status: verdict[:status], virus_name: verdict[:virus], **spam_attributes)
    Rails.logger.warn "[mail_on_rails] quarantined #{verdict[:status]} message for #{account.email}" \
                      "#{" (#{verdict[:virus]})" if verdict[:virus]}"
  end

  # A clean delivery supersedes "unscanned" review copies of the same
  # message left behind by 451 tempfails (clamd was down, the sender
  # retried, the retry scanned clean). Never touches "infected" rows.
  def sweep_stale_unscanned(account)
    mid = mail.message_id.to_s.presence
    return unless mid

    mailbox = account.find_mailbox(Mailbox::QUARANTINE)
    return unless mailbox

    swept = mailbox.email_messages.where(message_id: mid, scan_status: "unscanned").delete_all
    Rails.logger.info "[mail_on_rails] swept #{swept} stale unscanned quarantine copies for #{account.email}" if swept.positive?
  end

  def header_values(name)
    mail.header.fields.select { |field| field.name.casecmp?(name) }.map(&:value)
  end
end
