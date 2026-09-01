# frozen_string_literal: true

require_relative "test_helper"

# The outbound queue row's envelope goes onto the wire verbatim as MAIL
# FROM / RCPT TO, so it is validated at the model - whichever path queued
# it (SMTP edge, mailroom, report jobs, composer).
class SmtpOutboundMessageTest < DbSuite::TestCase
  def build(recipient: "friend@elsewhere.test", mail_from: "user@example.test")
    MailOnRails::SmtpOutboundMessage.new(mail_from: mail_from, recipient: recipient,
                                         data: "From: user@example.test\r\n\r\nhi",
                                         next_attempt_at: Time.current)
  end

  test "a plain envelope is valid, and the null return path is allowed" do
    assert build.valid?
    assert build(mail_from: "").valid?, "bounces and auto-replies use MAIL FROM:<>"
    assert build(recipient: "pelé@elsewhere.test").valid?, "SMTPUTF8 addresses are fine"
  end

  test "CR, LF, NUL and whitespace in the recipient are refused" do
    [ "a@b.test\r\nRCPT TO:<x@y.test>", "a@b.test\nDATA", "a@b.test\0", "a b@c.test", "a@b.test\t" ].each do |bad|
      message = build(recipient: bad)
      refute message.valid?, "#{bad.inspect} must be refused"
      assert_includes message.errors.attribute_names, :recipient
    end
  end

  test "the same characters in mail_from are refused; a blank recipient is refused" do
    [ "u@e.test\r\n", "u@e.test\0", "u e@e.test" ].each do |bad|
      refute build(mail_from: bad).valid?, "#{bad.inspect} must be refused"
    end
    refute build(recipient: "").valid?
    refute build(recipient: nil).valid?
  end

  test "create! raises on an injected envelope" do
    assert_raises(ActiveRecord::RecordInvalid) do
      MailOnRails::SmtpOutboundMessage.create!(mail_from: "user@example.test", recipient: "x@y.test\r\nQUIT",
                                               data: "hi", next_attempt_at: Time.current)
    end
  end
end
