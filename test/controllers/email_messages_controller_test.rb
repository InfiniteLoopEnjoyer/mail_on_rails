require "test_helper"
require "mail_on_rails/clamav_scanner"
require_relative "../test_helpers/clamav_stub_helper"

# The received-message view renders an analysis footer (SPF/DKIM/DMARC, the
# virus result, and the rspamd spam score) for mail that went through the
# inbound pipeline, and omits it for messages with no verdicts (e.g. Sent
# copies).
class EmailMessagesControllerTest < ActionDispatch::IntegrationTest
  include ClamavStubHelper

  RAW = "From: sender@remote.test\r\nTo: carol@example.com\r\n" \
        "Subject: hello\r\nMessage-ID: <m1@remote.test>\r\n\r\nbody\r\n"

  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
  end

  def show(message)
    get email_account_mailbox_email_message_url(@account, message.mailbox, message)
  end

  test "renders the analysis footer for an analyzed inbound message" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       auth_results: "mail.test; spf=pass; dkim=fail; dmarc=pass",
                                       scan_status: "clean", spam_score: 2.1, spam_threshold: 6.0,
                                       spam_action: "no action")
    show(message)

    assert_response :success
    assert_select "article footer", 1

    # Anchored on each badge's title rather than its label: the title is the
    # verdict itself ("SPF=pass"), while the visible wording is presentation
    # and has been restyled more than once.
    assert_select "article footer span[title=?]", "SPF=pass"
    assert_select "article footer span[title=?]", "DKIM=fail"
    assert_select "article footer span[title=?]", "DMARC=pass"

    footer = css_select("article footer").text
    assert_match "No virus", footer
    assert_match "✓ Spam score: 2.1 / 6.0 — no action", footer
    assert_select "article footer span.bg-green-100", text: /Spam score/
  end

  # rspamd verdicts that aren't "no action" keep the neutral slate pill, so
  # green stays reserved for a clean bill of health.
  test "a flagged spam action keeps the neutral badge without a check" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       scan_status: "clean", spam_score: 8.4, spam_threshold: 6.0,
                                       spam_action: "add header")
    show(message)

    footer = css_select("article footer").text
    assert_match "Spam score: 8.4 / 6.0 — add header", footer
    assert_no_match(/✓ Spam score/, footer)
    assert_select "article footer span.bg-green-100", text: /Spam score/, count: 0
  end

  # The scan-status badge is the one part of the footer with a branch per
  # outcome, and its wording is not derived from anything - assert the
  # strings so a template edit can't quietly change what a reader is told
  # about a message's safety.
  def footer_for(scan_status:, virus_name: nil)
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       auth_results: "mail.test; spf=pass",
                                       scan_status: scan_status, virus_name: virus_name)
    show(message)
    assert_response :success
    css_select("article footer").text
  end

  test "an infected message names the virus" do
    assert_match "☣ Eicar-Test-Signature", footer_for(scan_status: "infected",
                                                      virus_name: "Eicar-Test-Signature")
  end

  test "a message that arrived while the scanner was down is marked unscanned" do
    assert_match "⚠ Unscanned", footer_for(scan_status: "unscanned")
  end

  test "a message with no scan status is marked not scanned" do
    assert_match "⚠ Not scanned", footer_for(scan_status: nil)
  end

  test "viewing a message marks it as seen" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    assert_not message.seen?

    show(message)
    assert_response :success
    assert message.reload.seen?
    assert_select "[data-controller=mark-read]", 0

    show(message)
    assert_response :success
    assert_equal [ "\\Seen" ], message.reload.flags
  end

  test "a hover-prefetch does not mark the message seen" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)

    get email_account_mailbox_email_message_url(@account, message.mailbox, message),
        headers: { "X-Sec-Purpose" => "prefetch" }
    assert_response :success
    assert_not message.reload.seen?
    assert_select "[data-controller=mark-read]", 1
  end

  test "mark_read marks the message seen" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)

    post mark_read_email_account_mailbox_email_message_url(@account, message.mailbox, message)
    assert_response :no_content
    assert message.reload.seen?
  end

  # -- attachments -----------------------------------------------------------

  PDF_BYTES = "%PDF-1.4 pretend report".b

  def raw_with_attachment
    mail = Mail.new(from: "sender@remote.test", to: "carol@example.com",
                    subject: "with attachment", body: "see attached")
    mail.add_file filename: "report.pdf", content: PDF_BYTES
    mail.to_s
  end

  def attachment_url(message, index: 0)
    attachment_email_account_mailbox_email_message_url(@account, message.mailbox, message, index: index)
  end

  test "a clean message links each attachment with filename, type and size" do
    message = EmailMessage.deliver_raw(@account.inbox, raw_with_attachment, scan_status: "clean")
    show(message)

    assert_response :success
    assert_select "a[href=?]", attachment_email_account_mailbox_email_message_path(@account, message.mailbox, message, index: 0) do
      assert_select "span", text: "report.pdf"
      assert_select "span", text: "application/pdf · #{ActiveSupport::NumberHelper.number_to_human_size(PDF_BYTES.bytesize)}"
    end
  end

  test "an unscanned message lists attachments without a download link" do
    message = EmailMessage.deliver_raw(@account.inbox, raw_with_attachment, scan_status: "unscanned")
    show(message)

    assert_response :success
    section = css_select("article section").text
    assert_match "report.pdf", section
    assert_match "application/pdf", section
    assert_select "article section a", 0
    assert_select "[title=?]", "Not yet scanned for viruses - download disabled"
  end

  test "an infected message says why the download is disabled" do
    message = EmailMessage.deliver_raw(@account.inbox, raw_with_attachment,
                                       scan_status: "infected", virus_name: "Eicar-Test-Signature")
    show(message)

    assert_select "article section a", 0
    assert_select "[title=?]", "Virus detected - download disabled"
  end

  test "a message without attachments renders no attachments section" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW, scan_status: "clean")
    show(message)

    assert_select "article section", 0
  end

  test "downloads an attachment from a clean message" do
    message = EmailMessage.deliver_raw(@account.inbox, raw_with_attachment, scan_status: "clean")
    get attachment_url(message)

    assert_response :success
    assert_equal PDF_BYTES, response.body.b
    assert_equal "application/pdf", response.media_type
    assert_match(/attachment/, response.headers["Content-Disposition"])
    assert_match(/report\.pdf/, response.headers["Content-Disposition"])
  end

  # The view renders no link for these, so any request here is hand-crafted -
  # it must not hand over an unscanned or infected payload.
  test "refuses to download from unscanned and infected messages" do
    %w[unscanned infected].each do |status|
      message = EmailMessage.deliver_raw(@account.inbox, raw_with_attachment, scan_status: status)
      get attachment_url(message)
      assert_response :forbidden, "expected #{status} download to be refused"
    end
  end

  test "refuses to download from a never-scanned inbound message" do
    message = EmailMessage.deliver_raw(@account.inbox, raw_with_attachment)
    get attachment_url(message)
    assert_response :forbidden
  end

  # Sent copies never pass through the scanner, but the owner wrote them -
  # their own attachments stay downloadable.
  test "the owner's own Sent copy is downloadable despite never being scanned" do
    sent = @account.find_mailbox("Sent")
    message = EmailMessage.deliver_raw(sent, raw_with_attachment, authenticated_as: @account.email)
    show(message)
    assert_select "article section a", 1

    get attachment_url(message)
    assert_response :success
    assert_equal PDF_BYTES, response.body.b
  end

  test "an out-of-range attachment index is not found" do
    message = EmailMessage.deliver_raw(@account.inbox, raw_with_attachment, scan_status: "clean")
    get attachment_url(message, index: 5)
    assert_response :not_found
  end

  # -- manual (re)scan -------------------------------------------------------

  Result = MailOnRails::ClamavScanner::Result

  def rescan_url(message)
    rescan_email_account_mailbox_email_message_url(@account, message.mailbox, message)
  end

  test "an unscanned message offers a Scan now button; a scanned one offers Rescan" do
    unscanned = EmailMessage.deliver_raw(@account.inbox, RAW, scan_status: "unscanned")
    clean = EmailMessage.deliver_raw(@account.inbox, RAW.sub("m1@", "m2@"), scan_status: "clean")

    with_scanner(enabled: true, scan: ->(_) { raise "show must not scan" }) do
      show(unscanned)
      assert_select "form[action=?] button", rescan_email_account_mailbox_email_message_path(@account, unscanned.mailbox, unscanned), text: "Scan now"

      show(clean)
      assert_select "article footer button", text: "Rescan"
    end
  end

  # A message with no verdicts at all normally has no analysis footer; once
  # the scanner can vouch for it, the footer appears carrying the "Not
  # scanned" badge and the scan button.
  test "a never-analyzed message still gets the scan button" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)

    with_scanner(enabled: true, scan: ->(_) { raise "show must not scan" }) do
      show(message)
    end
    assert_select "article footer button", text: "Scan now"

    with_scanner(enabled: false) do
      show(message)
    end
    assert_select "article footer", 0
  end

  test "rescan records a clean verdict and clears the old virus name" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       scan_status: "unscanned", virus_name: "stale")

    with_scanner(enabled: true, scan: Result.new(:clean, nil)) do
      post rescan_url(message)
    end

    assert_redirected_to email_account_mailbox_email_message_url(@account, message.mailbox, message)
    assert_equal "No virus found.", flash[:notice]
    message.reload
    assert_equal "clean", message.scan_status
    assert_nil message.virus_name
  end

  test "rescan records an infected verdict" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW, scan_status: "clean")

    with_scanner(enabled: true, scan: Result.new(:infected, "Eicar-Test-Signature")) do
      post rescan_url(message)
    end

    assert_equal "Virus detected: Eicar-Test-Signature", flash[:notice]
    message.reload
    assert_equal "infected", message.scan_status
    assert_equal "Eicar-Test-Signature", message.virus_name
  end

  # A clamd hiccup must not downgrade a stored verdict.
  test "an unavailable scanner leaves the stored verdict untouched" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW, scan_status: "clean")

    with_scanner(enabled: true, scan: Result.new(:unavailable, nil)) do
      post rescan_url(message)
    end

    assert_redirected_to email_account_mailbox_email_message_url(@account, message.mailbox, message)
    assert_match(/scanner is unavailable/, flash[:alert])
    assert_equal "clean", message.reload.scan_status
  end

  test "the owner's own Sent copy is not rescannable" do
    sent = @account.find_mailbox("Sent")
    message = EmailMessage.deliver_raw(sent, RAW, authenticated_as: @account.email)

    with_scanner(enabled: true, scan: ->(_) { raise "must not scan" }) do
      show(message)
      assert_select "article footer", 0

      post rescan_url(message)
      assert_response :forbidden
    end
  end

  test "rescan is refused while scanning is disabled" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW, scan_status: "unscanned")

    with_scanner(enabled: false, scan: ->(_) { raise "must not scan" }) do
      post rescan_url(message)
    end
    assert_response :forbidden
    assert_equal "unscanned", message.reload.scan_status
  end

  # -- spam marking ----------------------------------------------------------

  test "mark_spam moves the message to Junk with all its verdicts" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       auth_results: "mail.test; spf=pass; dkim=pass; dmarc=pass",
                                       scan_status: "clean", spam_score: 2.1, spam_threshold: 6.0,
                                       spam_action: "no action")
    post mark_spam_email_account_mailbox_email_message_url(@account, @account.inbox, message)

    assert_redirected_to email_account_mailbox_url(@account, @account.inbox)
    assert_equal "Moved to Junk.", flash[:notice]
    assert_empty @account.inbox.email_messages
    moved = @account.find_mailbox("Junk").email_messages.sole
    assert_equal "mail.test; spf=pass; dkim=pass; dmarc=pass", moved.auth_results
    assert_equal "clean", moved.scan_status
    assert_equal 2.1, moved.spam_score
    assert_equal message.raw, moved.raw
  end

  test "unmark_spam moves a Junk message back to INBOX" do
    junk = @account.find_mailbox("Junk")
    message = EmailMessage.deliver_raw(junk, RAW)
    post unmark_spam_email_account_mailbox_email_message_url(@account, junk, message)

    assert_redirected_to email_account_mailbox_url(@account, junk)
    assert_equal "Moved to INBOX.", flash[:notice]
    assert_empty junk.email_messages
    assert_equal 1, @account.inbox.email_messages.count
  end

  test "mark_spam inside Junk and unmark_spam outside it are refused" do
    junk = @account.find_mailbox("Junk")
    junk_message = EmailMessage.deliver_raw(junk, RAW)
    post mark_spam_email_account_mailbox_email_message_url(@account, junk, junk_message)
    assert_response :forbidden

    inbox_message = EmailMessage.deliver_raw(@account.inbox, RAW.sub("m1@", "m2@"))
    post unmark_spam_email_account_mailbox_email_message_url(@account, @account.inbox, inbox_message)
    assert_response :forbidden
    assert_equal 1, junk.email_messages.count
    assert_equal 1, @account.inbox.email_messages.count
  end

  test "a draft cannot be marked as spam" do
    saved = EmailDraft.new(email_account_id: @account.id, to: "bob@remote.test",
                           subject: "Half written", body: "text").save
    post mark_spam_email_account_mailbox_email_message_url(@account, saved.mailbox, saved)
    assert_response :forbidden
  end

  test "the message page offers Mark as spam outside Junk and Not spam inside it" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    show(message)
    assert_select "form[action=?] button", mark_spam_email_account_mailbox_email_message_path(@account, @account.inbox, message), text: "Mark as spam"

    junk = @account.find_mailbox("Junk")
    junk_message = EmailMessage.deliver_raw(junk, RAW.sub("m1@", "m2@"))
    get email_account_mailbox_email_message_url(@account, junk, junk_message)
    assert_select "form[action=?] button", unmark_spam_email_account_mailbox_email_message_path(@account, junk, junk_message), text: "Not spam"
    assert_select "button", text: "Mark as spam", count: 0
  end

  # -- deleting --------------------------------------------------------------

  test "destroy moves the message to Trash with all its verdicts" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       auth_results: "mail.test; spf=pass; dkim=pass; dmarc=pass",
                                       scan_status: "clean", spam_score: 2.1, spam_threshold: 6.0,
                                       spam_action: "no action")
    delete email_account_mailbox_email_message_url(@account, @account.inbox, message)

    assert_redirected_to email_account_mailbox_url(@account, @account.inbox)
    assert_equal "Moved to Trash.", flash[:notice]
    assert_empty @account.inbox.email_messages
    moved = @account.find_mailbox("Trash").email_messages.sole
    assert_equal "mail.test; spf=pass; dkim=pass; dmarc=pass", moved.auth_results
    assert_equal "clean", moved.scan_status
    assert_equal message.raw, moved.raw
  end

  test "destroy inside Trash deletes permanently" do
    trash = @account.find_mailbox("Trash")
    message = EmailMessage.deliver_raw(trash, RAW)
    delete email_account_mailbox_email_message_url(@account, trash, message)

    assert_redirected_to email_account_mailbox_url(@account, trash)
    assert_equal "Message permanently deleted.", flash[:notice]
    assert_empty trash.email_messages
    assert_not EmailMessage.exists?(message.id)
  end

  test "destroy recreates a deleted Trash folder" do
    @account.find_mailbox("Trash").destroy!
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    delete email_account_mailbox_email_message_url(@account, @account.inbox, message)

    assert_equal message.raw, @account.find_mailbox("Trash").email_messages.sole.raw
  end

  test "the message page offers Delete outside Trash and a confirmed Delete forever inside it" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    show(message)
    assert_select "form[action=?] button", email_account_mailbox_email_message_path(@account, @account.inbox, message), text: "Delete"

    trash = @account.find_mailbox("Trash")
    trash_message = EmailMessage.deliver_raw(trash, RAW.sub("m1@", "m2@"))
    get email_account_mailbox_email_message_url(@account, trash, trash_message)
    assert_select "form[action=?][data-turbo-confirm] button",
                  email_account_mailbox_email_message_path(@account, trash, trash_message), text: "Delete forever"
    assert_select "button", text: "Delete", count: 0
  end

  # -- reply composer --------------------------------------------------------

  test "the message page offers a reply composer prefilled from the message" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    show(message)

    assert_response :success
    assert_select "[data-controller='draft-autosave']", 1
    assert_select "input[name='composed_email[to]'][value=?]", "sender@remote.test"
    assert_select "input[name='composed_email[subject]'][value=?]", "Re: hello"
    assert_select "textarea[name='composed_email[body]']", /sender@remote\.test wrote:/
  end

  # The composer has to carry the threading headers through to submit, or a
  # reply sent from the web breaks the conversation for everyone else.
  test "the composer carries the threading headers" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    show(message)

    assert_select "input[name='composed_email[in_reply_to]'][value=?]", "m1@remote.test"
    assert_select "input[name='composed_email[draft_message_id]']", 1
  end

  test "omits the footer for a message with no verdicts" do
    sent = @account.find_mailbox("Sent")
    message = EmailMessage.deliver_raw(sent, RAW)
    show(message)

    assert_response :success
    assert_select "article footer", 0
  end

  # An unsent draft is something to keep writing, not something to reply to.
  test "a draft offers to continue writing instead of a reply composer" do
    saved = EmailDraft.new(email_account_id: @account.id, to: "bob@remote.test",
                           subject: "Half written", body: "Got this far.").save
    get email_account_mailbox_email_message_url(@account, saved.mailbox, saved)

    assert_response :success
    assert_select "[data-controller='draft-autosave']", 0
    assert_select "a[href=?]", edit_draft_path(saved), text: "Continue writing"
  end

  # --- HTML rendering: sanitized content inside a sandboxed iframe ---

  HTML_RAW = "From: sender@remote.test\r\nTo: carol@example.com\r\nSubject: rich\r\n" \
             "Content-Type: text/html; charset=UTF-8\r\n\r\n" \
             "<p>Hello <b>there</b></p><script>alert(1)</script>\r\n"

  TRACKED_RAW = "From: sender@remote.test\r\nTo: carol@example.com\r\nSubject: pixel\r\n" \
                "Content-Type: text/html; charset=UTF-8\r\n\r\n" \
                '<p>news</p><img src="https://tracker.test/p.png">' + "\r\n"

  def iframe_srcdoc
    frame = css_select("iframe").first
    assert frame, "expected an iframe on the page"
    frame["srcdoc"]
  end

  test "an HTML message renders sanitized inside a sandboxed iframe" do
    message = EmailMessage.deliver_raw(@account.inbox, HTML_RAW)
    show(message)

    assert_response :success
    assert_select "iframe[sandbox=?]", "allow-popups allow-popups-to-escape-sandbox"
    assert_includes iframe_srcdoc, "<b>there</b>"
    assert_not_includes iframe_srcdoc, "alert"
    assert_select "a", text: "View plain text"
  end

  test "a plain-text message renders without an iframe" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    show(message)

    assert_select "iframe", 0
    assert_select "article pre", text: /body/
    assert_select "a", text: "View HTML", count: 0
  end

  test "view=text falls back to the text body with a way back to HTML" do
    message = EmailMessage.deliver_raw(@account.inbox, HTML_RAW)
    get email_account_mailbox_email_message_url(@account, message.mailbox, message, view: "text")

    assert_select "iframe", 0
    assert_select "article pre"
    assert_select "a[href=?]", email_account_mailbox_email_message_path(@account, message.mailbox, message),
                  text: "View HTML"
  end

  test "remote images are blocked until the reader opts in" do
    message = EmailMessage.deliver_raw(@account.inbox, TRACKED_RAW)
    show(message)

    assert_not_includes iframe_srcdoc, "tracker.test"
    assert_select "a[href=?]", email_account_mailbox_email_message_path(@account, message.mailbox, message, images: 1),
                  text: "Load remote images"

    get email_account_mailbox_email_message_url(@account, message.mailbox, message, images: 1)

    assert_includes iframe_srcdoc, "https://tracker.test/p.png"
    assert_select "a", text: "Load remote images", count: 0
  end
end
