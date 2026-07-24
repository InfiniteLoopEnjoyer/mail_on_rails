class EmailMessage < ApplicationRecord
  belongs_to :mailbox

  serialize :flags, coder: JSON

  validates :uid, presence: true, uniqueness: { scope: :mailbox_id }

  # Stores a raw RFC822 message into a mailbox, extracting the header
  # fields the web UI needs for listing. authenticated_as records the
  # trusted sender (nil = accepted unauthenticated / potentially spoofed).
  def self.deliver_raw(mailbox, raw, flags: [], internal_date: nil, authenticated_as: nil, auth_results: nil,
                       scan_status: nil, virus_name: nil, spam_score: nil, spam_threshold: nil, spam_action: nil)
    raw = raw.gsub(/(?<!\r)\n/, "\r\n") # normalize bare LF to CRLF
    mail = Mail.read_from_string(raw) rescue nil

    mailbox.email_messages.create!(
      uid: mailbox.claim_uid!,
      raw: raw,
      size: raw.bytesize,
      flags: flags,
      internal_date: internal_date || mail&.date&.to_time || Time.current,
      message_id: mail&.message_id.to_s.presence,
      subject: mail&.subject.to_s.presence,
      from_address: (mail&.from || []).first,
      to_addresses: (mail&.to || []).join(", "),
      authenticated_as: authenticated_as,
      auth_results: auth_results,
      scan_status: scan_status,
      virus_name: virus_name,
      spam_score: spam_score,
      spam_threshold: spam_threshold,
      spam_action: spam_action
    )
  end

  # True when the sender authenticated, i.e. the From is verified, not spoofed.
  def authenticated?
    authenticated_as.present?
  end

  # One of "pass"/"fail"/"none"/... - parsed out of the recorded
  # Authentication-Results-style string (the app computes these SPF/DKIM/DMARC
  # verdicts via rspamd; the exim edge only forwards the connection facts).
  def auth_result(mechanism)
    auth_results.to_s[/\b#{mechanism}=(\w+)/, 1]
  end

  # A local authenticated submitter, or a remote sender whose visible
  # From: domain passed DMARC - either way the From is not spoofed.
  def sender_verified?
    authenticated? || auth_result("dmarc") == "pass"
  end

  def seen?
    flags.include?("\\Seen")
  end

  # True once the inbound pipeline recorded any verdict (sender-auth, virus,
  # or spam). Received mail has these; outbound Sent copies don't. Gates the
  # analysis footer in the message view.
  def analyzed?
    scan_status.present? || auth_results.present? || spam_score.present?
  end

  def parsed
    @parsed ||= Mail.read_from_string(raw)
  end

  # Best-effort plain-text body for the web UI.
  def text_body
    mail = parsed
    part = mail.text_part || (mail unless mail.multipart?)
    if part
      body = part.body.decoded
      charset = part.charset || "UTF-8"
      body.force_encoding(charset).encode("UTF-8", invalid: :replace, undef: :replace)
    else
      html = mail.html_part&.body&.decoded
      html ? html.gsub(/<[^>]+>/, " ").squish : ""
    end
  rescue StandardError
    raw.to_s.split(/\r?\n\r?\n/, 2).last.to_s
  end
end
