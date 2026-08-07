require "test_helper"

# EmailMessage#html_body: which MIME part becomes the HTML rendering, and
# the vouching gate on cid-inlined images (same rule as attachment
# downloads: only a clean scan or the owner's own writing serves bytes).
class EmailMessageHtmlTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
  end

  def deliver(mail, **options)
    EmailMessage.deliver_raw(@account.inbox, mail.to_s, **options)
  end

  def alternative_mail(html)
    Mail.new do
      from "sender@remote.test"
      to "carol@example.com"
      subject "hello"
      text_part { body "plain version" }
      html_part do
        content_type "text/html; charset=UTF-8"
        body html
      end
    end
  end

  test "multipart/alternative uses the html part, sanitized" do
    message = deliver(alternative_mail("<p>Hello <b>rich</b></p><script>alert(1)</script>"))

    assert message.html_part?
    assert_includes message.html_body.html, "<b>rich</b>"
    assert_not_includes message.html_body.html, "alert"
    assert_equal "plain version", message.text_body
  end

  test "a single-part text/html message renders as HTML" do
    raw = "From: sender@remote.test\r\nTo: carol@example.com\r\nSubject: x\r\n" \
          "Content-Type: text/html; charset=UTF-8\r\n\r\n<p>only html</p>\r\n"
    message = EmailMessage.deliver_raw(@account.inbox, raw)

    assert message.html_part?
    assert_includes message.html_body.html, "<p>only html</p>"
  end

  test "a plain-text message has no HTML rendering" do
    raw = "From: sender@remote.test\r\nTo: carol@example.com\r\nSubject: x\r\n\r\njust text\r\n"
    message = EmailMessage.deliver_raw(@account.inbox, raw)

    assert_not message.html_part?
    assert_nil message.html_body
  end

  def mail_with_inline_image
    mail = alternative_mail('<p>chart:</p><img src="cid:pic1">')
    image = Mail::Part.new do
      content_type 'image/png; name="pic.png"'
      content_transfer_encoding "base64"
      body Base64.encode64("PNGBYTES")
    end
    image.content_id = "<pic1>"
    mail.add_part(image)
    mail
  end

  test "cid images embed as data URIs on a scanned-clean message" do
    message = deliver(mail_with_inline_image, scan_status: "clean")

    assert_includes message.html_body.html, "data:image/png;base64,#{Base64.strict_encode64("PNGBYTES")}"
  end

  test "cid images stay dead on an unscanned message" do
    message = deliver(mail_with_inline_image)

    assert_not message.attachments_downloadable?
    assert_not_includes message.html_body.html, "data:image/png"
    assert_not_includes message.html_body.html, "cid:"
  end

  test "remote image opt-in flows through to the sanitizer" do
    message = deliver(alternative_mail('<img src="https://cdn.test/logo.png">'))

    assert_not_includes message.html_body.html, "cdn.test"
    assert_includes message.html_body(allow_remote_images: true).html, "https://cdn.test/logo.png"
  end

  test "html part charset is converted to UTF-8" do
    mail = Mail.new do
      from "sender@remote.test"
      to "carol@example.com"
      subject "hello"
      text_part { body "plain version" }
      html_part do
        content_type "text/html; charset=ISO-8859-1"
        body "<p>caf\xE9</p>".dup.force_encoding("BINARY")
      end
    end
    message = deliver(mail)

    assert_includes message.html_body.html, "café"
  end
end
