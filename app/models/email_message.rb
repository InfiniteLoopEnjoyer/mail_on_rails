class EmailMessage < ApplicationRecord
  belongs_to :mailbox

  serialize :flags, coder: JSON

  validates :uid, presence: true, uniqueness: { scope: :mailbox_id }

  # Stores a raw RFC822 message into a mailbox, extracting the header
  # fields the web UI needs for listing. authenticated_as records the
  # trusted sender (nil = accepted unauthenticated / potentially spoofed).
  def self.deliver_raw(mailbox, raw, flags: [], internal_date: nil, authenticated_as: nil, auth_results: nil)
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
      auth_results: auth_results
    )
  end

  # True when the sender authenticated, i.e. the From is verified, not spoofed.
  def authenticated?
    authenticated_as.present?
  end

  # One of "pass"/"fail"/"none"/... - parsed out of the recorded
  # Authentication-Results-style string (see MailOnRails::Smtp::SenderAuth
  # in the mail_on_rails_smtp gem).
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
