require "mail_on_rails/smtp/send_quota"

# Sends an account's vacation auto-reply for an inbound message, with the
# RFC 3834 loop protections that keep autoresponders from mailbombing
# each other:
#
#   - never answer bounces or the null sender (MAILER-DAEMON and friends);
#   - never answer anything itself auto-generated (Auto-Submitted,
#     X-Auto-Response-Suppress, Precedence: bulk/list/junk);
#   - never answer mailing-list traffic (List-* headers);
#   - never answer the account's own mail;
#   - one reply per correspondent per REPLY_WINDOW, not one per message;
#   - each reply consumes a slot of the account's outbound send quota, so
#     a vacationing account is bounded exactly like a sending one.
#
# The reply is addressed to the envelope return path (RFC 3834 section 4)
# - the one address the sending MTA had to be able to receive at - never
# to the freely forgeable Reply-To/From headers, so a stranger can't aim
# our DKIM-signed auto-replies at a third party. It is sent with the null
# envelope sender, so the reply is itself unbounceable, and marked
# Auto-Submitted: auto-replied (so other compliant responders won't
# answer it back). It rides the normal outbound path: SmtpOutboundMessage
# for remote senders, direct INBOX delivery for local ones.
module VacationResponder
  REPLY_WINDOW = 7.days

  module_function

  # +mail+ is the parsed inbound message, +return_path+ its envelope
  # sender (the mailroom knows it from the edge stamp). Returns true when
  # a reply went out.
  def deliver_if_due(account, mail, return_path:, quota: MailOnRails::Smtp::SendQuota.shared)
    return false unless account.vacation_active?
    return false if bounce?(return_path) || auto_generated?(mail) || list_traffic?(mail)

    recipient = return_path.to_s.strip.delete("<>")
    return false if own_address?(account, recipient)

    # The free pre-check keeps repeat mail from a within-window
    # correspondent from burning quota slots; the atomic claim comes
    # after the quota so an exhausted quota doesn't suppress the
    # correspondent for the whole window without ever replying.
    claim_key = VacationReply.normalize(recipient)
    return false if VacationReply.replied_recently?(account, claim_key, window: REPLY_WINDOW)

    if quota && !quota.consume(account.email)
      Rails.logger.warn "[mail_on_rails] vacation reply from #{account.email} skipped: send quota exhausted"
      return false
    end
    return false unless VacationReply.claim(account, claim_key, window: REPLY_WINDOW)

    raw = build_reply(account, mail, recipient)
    if (inbox = local_inbox(recipient))
      EmailMessage.deliver_raw(inbox, raw, authenticated_as: account.email)
    else
      # Null envelope sender per RFC 3834: an undeliverable auto-reply
      # must vanish, not bounce back to the vacationing account.
      SmtpOutboundMessage.create!(mail_from: "", recipient: recipient,
                                  data: raw, next_attempt_at: Time.current)
    end
    Rails.logger.info "[mail_on_rails] vacation reply sent from #{account.email} to #{recipient}"
    true
  end

  # The null sender marks bounces and delivery reports (RFC 5321) - the
  # one class of mail an autoresponder must never answer. Daemon-style
  # local parts catch the MTAs that bounce with a real address.
  def bounce?(return_path)
    address = return_path.to_s.strip.delete("<>")
    address.empty? || address.split("@").first&.casecmp?("mailer-daemon") || address.split("@").first&.casecmp?("postmaster")
  end

  # Auto-Submitted: anything but "no" is itself an automatic message
  # (RFC 3834 section 2). Precedence bulk/list/junk is the older
  # convention; X-Auto-Response-Suppress is Exchange's.
  def auto_generated?(mail)
    auto_submitted = header(mail, "Auto-Submitted")
    return true if auto_submitted.present? && !auto_submitted.casecmp?("no")
    return true if header(mail, "Precedence").to_s.match?(/\A(bulk|list|junk)\z/i)

    header(mail, "X-Auto-Response-Suppress").to_s.match?(/\b(All|OOF)\b/i)
  end

  def list_traffic?(mail)
    %w[List-Id List-Post List-Unsubscribe].any? { |name| header(mail, name).present? }
  end

  def own_address?(account, address)
    normalized = address.to_s.strip.downcase
    account.email == normalized || account.email_aliases.exists?(email: normalized)
  end

  def local_inbox(recipient)
    address = recipient.to_s.downcase
    local = EmailAccount.find_by(email: address) ||
            EmailAlias.find_by(email: address)&.email_account
    local&.inbox
  end

  def build_reply(account, original, recipient)
    reply = Mail.new
    reply.from    = account.name.present? ? "#{account.name} <#{account.email}>" : account.email
    reply.to      = recipient
    reply.subject = account.vacation_subject.presence || "Automatic reply: #{original.subject}".strip
    reply.date    = Time.current
    reply.body    = account.vacation_body.to_s
    # Thread the reply under the message it answers, and mark it as the
    # automatic answer it is so compliant responders stay quiet.
    if original.message_id.present?
      reply.in_reply_to = "<#{original.message_id}>"
      reply.references  = "<#{original.message_id}>"
    end
    reply.header["Auto-Submitted"] = "auto-replied"
    reply.header["X-Auto-Response-Suppress"] = "All"
    reply.to_s
  end

  def header(mail, name)
    field = mail.header.fields.find { |f| f.name.casecmp?(name) }
    field&.value.to_s.strip.presence
  end
end
