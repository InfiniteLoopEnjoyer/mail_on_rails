# frozen_string_literal: true

require_relative "test_helper"

# RFC 3464 report structure for the three DSN kinds, and the queue row's
# RFC 3461 request helpers they are gated on.
class DeliveryStatusNotificationTest < DbSuite::TestCase
  RAW = "From: carol@example.com\r\nTo: out@remote.test\r\n" \
        "Subject: hello\r\nMessage-ID: <m1@example.com>\r\n\r\nsecret body\r\n"

  def outbound(**attrs)
    MailOnRails::SmtpOutboundMessage.create!(
      mail_from: "carol@example.com", recipient: "out@remote.test",
      data: RAW, next_attempt_at: Time.current, attempts: 3, **attrs
    )
  end

  def parse(notice)
    Mail.read_from_string(notice.to_s)
  end

  def status_part(mail)
    mail.parts.find { |part| part.content_type.start_with?("message/delivery-status") }.body.to_s
  end

  test "a failure DSN is a multipart/report with per-recipient fields" do
    notice = MailOnRails::DeliveryStatusNotification.failure(
      message: outbound(dsn_envid: "QQ+2B314159", dsn_orcpt: "rfc822;out+2Bplus@remote.test"),
      error: "mx.remote.test: 550 5.1.1 no such user"
    )
    mail = parse(notice)

    assert_match(/multipart\/report/, mail.content_type)
    assert_match(/report-type=delivery-status/, mail.content_type)
    assert_equal "carol@example.com", mail.to.first
    assert_match(/\Amailer-daemon@example\.com\z/, mail.from.first)
    assert_equal "auto-generated", mail.header["Auto-Submitted"].value

    status = status_part(mail)
    assert_includes status, "Reporting-MTA: dns;"
    # xtext +XX escapes decoded (RFC 3464 2.2.1)
    assert_includes status, "Original-Envelope-Id: QQ+314159"
    assert_includes status, "Original-Recipient: rfc822;out+plus@remote.test"
    assert_includes status, "Final-Recipient: rfc822; out@remote.test"
    assert_includes status, "Action: failed"
    assert_includes status, "Status: 5.1.1"
    assert_includes status, "Diagnostic-Code: smtp; mx.remote.test: 550 5.1.1 no such user"
  end

  test "a failure DSN returns headers only unless RET=FULL was requested" do
    headers_only = parse(MailOnRails::DeliveryStatusNotification.failure(message: outbound, error: "550 nope"))
    original = headers_only.parts.last
    assert_match(/text\/rfc822-headers/, original.content_type)
    refute_includes original.body.to_s, "secret body"

    full = parse(MailOnRails::DeliveryStatusNotification.failure(message: outbound(dsn_ret: "FULL"),
                                                                 error: "550 nope"))
    original = full.parts.last
    assert_match(/message\/rfc822/, original.content_type)
    assert_includes original.body.to_s, "secret body"
  end

  test "a stale transient code never survives onto a final failure" do
    notice = MailOnRails::DeliveryStatusNotification.failure(message: outbound,
                                                             error: "timeout then 4.7.1 greylisted")
    assert_includes status_part(parse(notice)), "Status: 5.0.0"
  end

  test "a delayed DSN says delayed and when retries end" do
    notice = MailOnRails::DeliveryStatusNotification.delayed(message: outbound, error: "connection timed out")
    status = status_part(parse(notice))
    assert_includes status, "Action: delayed"
    assert_includes status, "Status: 4.0.0"
    assert_includes status, "Will-Retry-Until:"
  end

  test "a success DSN reports relayed by default" do
    status = status_part(parse(MailOnRails::DeliveryStatusNotification.success(message: outbound)))
    assert_includes status, "Action: relayed"
    assert_includes status, "Status: 2.0.0"
  end

  # -- the queue row's request helpers ---------------------------------------

  test "notify defaults: failure and delay on, success off" do
    row = outbound
    assert row.wants_failure_dsn?
    assert row.wants_delay_dsn?
    assert_not row.wants_success_dsn?
  end

  test "NOTIFY=NEVER suppresses every DSN" do
    row = outbound(dsn_notify: "NEVER")
    assert_not row.wants_failure_dsn?
    assert_not row.wants_delay_dsn?
    assert_not row.wants_success_dsn?
  end

  test "an explicit NOTIFY list is honored exactly" do
    row = outbound(dsn_notify: "SUCCESS,DELAY")
    assert_not row.wants_failure_dsn?
    assert row.wants_delay_dsn?
    assert row.wants_success_dsn?
  end
end
