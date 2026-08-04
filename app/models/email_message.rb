class EmailMessage < ApplicationRecord
  belongs_to :mailbox

  serialize :flags, coder: JSON

  validates :uid, presence: true, uniqueness: { scope: :mailbox_id }

  # CONDSTORE/QRESYNC (RFC 7162): every content mutation carries the
  # mailbox's next mod-sequence so IMAP clients can sync incrementally;
  # destroys additionally leave a tombstone for VANISHED (EARLIER).
  before_create { self.modseq = mailbox.claim_modseq! }
  after_update :bump_modseq_on_flag_change
  after_destroy :record_tombstone

  # Any message change (delivery, flag change, expunge) live-refreshes the
  # folder's message list, the account page's per-folder unread counts, and
  # the accounts index's unread badges.
  after_commit :broadcast_page_refreshes

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
      # OBJECTID (RFC 8474): content-derived, so COPY/MOVE (which
      # re-deliver the same bytes) preserve the EMAILID.
      email_object_id: "E#{Digest::SHA256.hexdigest(raw)[0, 24]}",
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

  def mark_seen!
    update!(flags: flags | [ "\\Seen" ]) unless seen?
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

  # An unsent message the user is still writing. \Draft is the flag every
  # mail client sets for this, so it - not the folder name - is what
  # decides whether the web UI opens a message to read or to keep writing.
  def draft?
    flags.any? { |flag| flag.casecmp?("\\Draft") }
  end

  # RFC 5322 threading ancestry, read from the raw message rather than
  # denormalised into a column like subject and from are: it is only ever
  # needed to build the References of a reply.
  def references
    Array(parsed.references).join(" ").presence
  rescue StandardError
    nil
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

  private

  def bump_modseq_on_flag_change
    update_column(:modseq, mailbox.claim_modseq!) if saved_change_to_flags?
  end

  def record_tombstone
    return if destroyed_by_association

    ExpungedMessage.record!(mailbox, uid, mailbox.claim_modseq!)
  end

  def broadcast_page_refreshes
    broadcast_refresh_later_to mailbox
    broadcast_refresh_later_to mailbox.email_account
    broadcast_refresh_later_to :email_accounts
  end
end
