# frozen_string_literal: true

require_relative "test_helper"

# deliver_raw and the web-facing body accessors treat the Mail gem's
# parse as untrusted: a hostile MIME structure (thousands of nested
# multipart levels - SystemStackError, which no `rescue StandardError`
# catches) or a header the gem hands back in an unexpected shape (`To:
# <<<` comes back as a raw String) must cost the message its rendering,
# never its delivery.
class EmailMessageParseTest < DbSuite::TestCase
  HEADERS = "Message-ID: <deep@remote.test>\r\nFrom: x@remote.test\r\nTo: a@example.test\r\nSubject: deep\r\nMIME-Version: 1.0\r\n"

  def nested(depth)
    raw = +"#{HEADERS}Content-Type: multipart/mixed; boundary=b0\r\n\r\n"
    depth.times { |i| raw << "--b#{i}\r\nContent-Type: multipart/mixed; boundary=b#{i + 1}\r\n\r\n" }
    raw << "--b#{depth}\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b#{depth}--\r\n"
    depth.times { |i| raw << "--b#{depth - 1 - i}--\r\n" }
    raw
  end

  def setup
    super
    @account = MailOnRails::EmailAccount.create!(email: "a@example.test", password: "pw-123456")
    @inbox = @account.inbox
  end

  def deliver(raw)
    MailOnRails::EmailMessage.deliver_raw(@inbox, raw)
  end

  def elapsed
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  [ 2000, 5000 ].each do |depth|
    test "a depth-#{depth} MIME tree is delivered opaque, fast, and renders without walking it" do
      message = nil
      seconds = elapsed { message = deliver(nested(depth)) }

      assert_operator seconds, :<, 1.0, "delivery took #{seconds.round(2)}s"
      assert message.persisted?
      assert_equal "<deep@remote.test>".delete("<>"), message.message_id
      assert_equal "deep", message.subject
      assert_equal "x@remote.test", message.from_address
      assert_equal "", message.body_text, "no body text is extracted past the cap"
      assert message.mime_too_complex?

      seconds = elapsed do
        assert_equal MailOnRails::EmailMessage::TOO_COMPLEX_NOTICE, message.text_body
        assert_nil message.html_body
        assert_not message.html_part?
        assert_equal [], message.attachments
      end
      assert_operator seconds, :<, 1.0, "rendering took #{seconds.round(2)}s"
    end
  end

  test "a message at the depth cap is still parsed normally" do
    message = deliver(nested(MailOnRails::MimeLimits::MAX_DEPTH - 1))

    assert_not message.mime_too_complex?
    assert_equal "hello", message.body_text.strip
    assert_equal "hello", message.text_body.strip
  end

  test "a Mail-gem blow-up inside a body walk is contained, SystemStackError included" do
    message = deliver("#{HEADERS}Content-Type: text/plain\r\n\r\nhello\r\n")
    exploding = Object.new
    exploding.define_singleton_method(:text_part) { raise SystemStackError, "stack level too deep" }
    exploding.define_singleton_method(:html_part) { raise SystemStackError, "stack level too deep" }
    exploding.define_singleton_method(:multipart?) { true }
    exploding.define_singleton_method(:attachments) { raise SystemStackError, "stack level too deep" }
    message.instance_variable_set(:@parsed, exploding)

    assert_equal "hello", message.text_body.strip, "falls back to the raw body"
    assert_nil message.html_body
    assert_not message.html_part?
    assert_equal [], message.attachments
    assert_equal "", MailOnRails::EmailMessage.plain_text(exploding, "X: y\r\n\r\n").to_s
  end

  test "an unparseable To: header does not raise and stores no garbage address" do
    raw = "Message-ID: <m1@remote.test>\r\nFrom: <\r\nTo: <<<\r\nSubject: hi\r\n\r\nbody\r\n"
    message = deliver(raw)

    assert message.persisted?
    assert_nil message.from_address, "the Mail gem's raw String for an unparseable From must not become an address"
    assert_equal "", message.to_addresses
    assert_equal "hi", message.subject
    assert_equal "body", message.body_text.strip
  end

  test "address_list keeps addr-specs and drops the raw-String shape" do
    assert_equal [ "a@b.test", "c@d.test" ], MailOnRails::EmailMessage.address_list([ "a@b.test", "c@d.test" ])
    assert_equal [], MailOnRails::EmailMessage.address_list("a@b.test, <")
    assert_equal [], MailOnRails::EmailMessage.address_list(nil)
    assert_equal [ "ok@b.test" ], MailOnRails::EmailMessage.address_list([ "<", "ok@b.test", "bob" ])
  end
end
