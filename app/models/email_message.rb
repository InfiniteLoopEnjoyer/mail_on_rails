require "mail_on_rails/clamav_scanner"

class EmailMessage < ApplicationRecord
  # Raised by deliver_raw when storing the message would push the account
  # past its storage quota (EmailAccount#quota_bytes).
  class OverQuota < StandardError; end

  belongs_to :mailbox

  serialize :flags, coder: JSON

  validates :uid, presence: true, uniqueness: { scope: :mailbox_id }

  # CONDSTORE/QRESYNC (RFC 7162): every content mutation carries the
  # mailbox's next mod-sequence so IMAP clients can sync incrementally;
  # destroys additionally leave a tombstone for VANISHED (EARLIER).
  before_create { self.modseq = mailbox.claim_modseq! }
  after_update :bump_modseq_on_flag_change
  after_destroy :record_tombstone

  # Storage accounting: the account's used_bytes tracks the sum of its
  # message sizes incrementally (atomic SQL increments), so the quota
  # check on delivery is a column read, not an aggregate over raw bytes.
  after_create { EmailAccount.update_counters(mailbox.email_account_id, used_bytes: size) }
  after_destroy { EmailAccount.update_counters(mailbox.email_account_id, used_bytes: -size) }

  # Any message change (delivery, flag change, expunge) live-refreshes the
  # folder's message list, the account page's per-folder unread counts, and
  # the accounts index's unread badges.
  after_commit :broadcast_page_refreshes

  # Bounds body_text at write time (in characters). The generated
  # search_vector column re-caps in SQL, but an unbounded write could
  # push the tsvector past Postgres's 1 MiB limit and turn a huge inbound
  # message into a failed delivery.
  SEARCHABLE_TEXT_LIMIT = 100_000

  # Full-text search over the stored search_vector (subject, from, to,
  # body_text). websearch_to_tsquery gives "words, "quoted phrases",
  # OR, -exclusions" semantics and never raises on user input.
  scope :full_text_search, ->(query) {
    where("email_messages.search_vector @@ websearch_to_tsquery('simple', ?)", query.to_s)
  }

  # Stores a raw RFC822 message into a mailbox, extracting the header
  # fields the web UI needs for listing. authenticated_as records the
  # trusted sender (nil = accepted unauthenticated / potentially spoofed).
  def self.deliver_raw(mailbox, raw, flags: [], internal_date: nil, authenticated_as: nil, auth_results: nil,
                       scan_status: nil, virus_name: nil, spam_score: nil, spam_threshold: nil, spam_action: nil,
                       enforce_quota: true)
    raw = raw.gsub(/(?<!\r)\n/, "\r\n") # normalize bare LF to CRLF

    # The central storage-quota gate: every write path (SMTP DATA via the
    # mailroom, IMAP APPEND/COPY, the composer) lands here. Same-account
    # moves pass enforce_quota: false - they are net-zero, and refusing
    # "move to Trash" on a full account would lock the user out of
    # freeing space. Concurrent deliveries can overshoot by one message;
    # a quota is a bound, not an invariant.
    account = mailbox.email_account
    if enforce_quota && account.quota_exceeded_by?(raw.bytesize)
      raise OverQuota, "#{account.email} is over its storage quota"
    end

    mail = Mail.read_from_string(raw) rescue nil
    # OBJECTID (RFC 8474): content-derived, so COPY/MOVE (which re-deliver
    # the same bytes) preserve the EMAILID.
    email_object_id = "E#{Digest::SHA256.hexdigest(raw)[0, 24]}"

    mailbox.email_messages.create!(
      uid: mailbox.claim_uid!,
      raw: raw,
      size: raw.bytesize,
      email_object_id: email_object_id,
      flags: flags,
      internal_date: internal_date || mail&.date&.to_time || Time.current,
      message_id: mail&.message_id.to_s.presence,
      subject: mail&.subject.to_s.presence,
      from_address: (mail&.from || []).first,
      to_addresses: (mail&.to || []).join(", "),
      body_text: searchable_text(raw, mail: mail),
      **thread_columns(mailbox.email_account, mail, email_object_id),
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
  # verdicts via rspamd; the SMTP edge only forwards the connection facts).
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

  # rspamd called it spam - the stored-column mirror of
  # RspamdAnalyzer::Result#spam?: any action past plain
  # acceptance/greylisting.
  def spam?
    spam_action.present? && ![ "no action", "greylist" ].include?(spam_action)
  end

  # Re-delivers this message into another mailbox of the same account and
  # removes it here (IMAP MOVE semantics: new UID + tombstone, EMAILID
  # preserved because it is content-derived). Every recorded verdict moves
  # with it - the analysis happened to the bytes, not to the folder.
  # Returns the new row.
  def move_to!(dest)
    moved = nil
    transaction do
      # enforce_quota: false - a move within the account is net-zero.
      moved = EmailMessage.deliver_raw(dest, raw, flags: flags, internal_date: internal_date,
                                       authenticated_as: authenticated_as, auth_results: auth_results,
                                       scan_status: scan_status, virus_name: virus_name,
                                       spam_score: spam_score, spam_threshold: spam_threshold,
                                       spam_action: spam_action, enforce_quota: false)
      destroy!
    end
    moved
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

  # Attachment metadata for the web UI. The MIME position keys the download
  # URL - filenames repeat and would need escaping rules; a position needs
  # neither.
  Attachment = Data.define(:index, :filename, :content_type, :size)

  def attachments
    @attachments ||= begin
      parsed.attachments.each_with_index.map do |part, index|
        Attachment.new(index: index,
                       filename: part.filename.presence || "attachment-#{index + 1}",
                       content_type: part.mime_type.presence || "application/octet-stream",
                       size: part.body.decoded.bytesize)
      end
    rescue StandardError
      []
    end
  end

  # Attachments open only once something vouched for the message: clamav
  # pronounced it clean, or the mailbox owner wrote it themselves (Sent
  # copies and drafts never pass through the scanner). Infected, "unscanned"
  # (scanner was down), and never-scanned mail render without links.
  def attachments_downloadable?
    scan_status == "clean" || authored_by_owner?
  end

  # Gates the manual scan button and its endpoint: any message can be
  # (re)scanned while the scanner is on, except the owner's own writing
  # (Sent copies, drafts) - there authorship, not a verdict, is what
  # vouches, and a scan banner on your own mail would only mislead.
  def rescannable?
    MailOnRails::ClamavScanner.enabled? && !draft? && !authored_by_owner?
  end

  # RFC 5322 threading ancestry (space-joined message-ids), denormalised
  # into references_ids at delivery time; feeds reply building and
  # threading.
  def references
    references_ids
  end

  # The threading columns for a message about to be stored: its ancestry
  # headers plus the thread_id they resolve to.
  def self.thread_columns(account, mail, fallback_anchor)
    in_reply_to = Array(mail&.in_reply_to).first.to_s.presence
    references = Array(mail&.references).map(&:to_s).reject(&:empty?)
    {
      in_reply_to: in_reply_to,
      references_ids: references.join(" ").presence,
      thread_id: resolve_thread_id(account, references, in_reply_to, mail&.message_id.to_s.presence, fallback_anchor)
    }
  end

  # A reply adopts the thread of any ancestor already stored in the
  # account (RFC 8474 THREADID is account-wide, not per-mailbox, so
  # copies and Sent counterparts land in the same thread). With no stored
  # ancestor the id derives deterministically from the chain's root (the
  # first reference) or the message's own id - so a thread converges on
  # one id even when its messages arrive out of order - and a message
  # with neither falls back to its content hash: a thread of its own.
  def self.resolve_thread_id(account, references, in_reply_to, message_id, fallback_anchor)
    ancestors = (references + [ in_reply_to ]).compact.uniq
    if ancestors.any?
      parent = joins(:mailbox).where(mailboxes: { email_account_id: account.id }, message_id: ancestors)
                              .where.not(thread_id: nil).order(:id).first
      return parent.thread_id if parent
    end

    "T#{Digest::SHA256.hexdigest(ancestors.first || message_id || fallback_anchor)[0, 24]}"
  end

  # Best-effort plain-text body for the web UI.
  def text_body
    mail = begin
      parsed
    rescue StandardError
      nil
    end
    self.class.plain_text(mail, raw)
  end

  # The body_text column's value: the body as plain text, made safe for a
  # Postgres text column (valid UTF-8, no NULs) and bounded so the
  # generated tsvector over it can't blow the delivery INSERT.
  def self.searchable_text(raw, mail: nil)
    mail ||= begin
      Mail.read_from_string(raw)
    rescue StandardError
      nil
    end
    text = plain_text(mail, raw)
    text.dup.force_encoding(Encoding::UTF_8).scrub.delete("\u0000")[0, SEARCHABLE_TEXT_LIMIT].to_s
  end

  # The body as displayable/searchable plain text: the text part when the
  # message has one, the tag-stripped HTML otherwise (including single-part
  # text/html messages), and the raw bytes past the header split when
  # parsing failed (mail: nil included).
  def self.plain_text(mail, raw)
    part = mail.text_part || (mail if !mail.multipart? && mail.mime_type != "text/html")
    if part
      decoded_utf8(part)
    else
      html_part = mail.html_part || (mail if !mail.multipart? && mail.mime_type == "text/html")
      html = html_part && decoded_utf8(html_part)
      html ? html.gsub(/<[^>]+>/, " ").squish : ""
    end
  rescue StandardError
    raw.to_s.split(/\r?\n\r?\n/, 2).last.to_s
  end

  def self.decoded_utf8(part)
    body = part.body.decoded
    charset = part.charset || "UTF-8"
    body.force_encoding(charset).encode("UTF-8", invalid: :replace, undef: :replace)
  end

  # Cheap "does an HTML rendering exist" check for the view toggle.
  def html_part?
    html_source.present?
  rescue StandardError
    false
  end

  # Sanitised HTML body for the web UI (nil when the message has no HTML
  # part). Safety lives in EmailHtmlSanitizer plus the sandboxed iframe the
  # view puts the result in; remote images stay blocked unless the reader
  # asked for them on this visit.
  def html_body(allow_remote_images: false)
    part = html_source
    return nil unless part

    EmailHtmlSanitizer.sanitize(decoded_utf8(part),
                                inline_images: inline_images,
                                allow_remote_images: allow_remote_images)
  rescue StandardError
    nil
  end

  private

  def html_source
    mail = parsed
    mail.html_part || (mail if !mail.multipart? && mail.mime_type == "text/html")
  end

  # cid:-referenced images for html_body, keyed by bare Content-ID. Gated by
  # the same vouching rule as attachment downloads: embedding an image part
  # into the page is serving its bytes, so an unscanned or infected message
  # renders with its inline images dead just like its attachment links.
  def inline_images
    return {} unless attachments_downloadable? && parsed.multipart?

    parsed.all_parts.filter_map do |part|
      next unless part.content_id.present? && part.mime_type.to_s.start_with?("image/")

      cid = part.content_id.delete_prefix("<").delete_suffix(">")
      [ cid, EmailHtmlSanitizer::InlineImage.new(content_type: part.mime_type, data: part.body.decoded) ]
    end.to_h
  end

  def decoded_utf8(part)
    self.class.decoded_utf8(part)
  end

  def authored_by_owner?
    authenticated_as.present? && authenticated_as.casecmp?(mailbox.email_account.email)
  end

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
