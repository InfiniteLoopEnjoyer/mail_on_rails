# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/aggregate_report"

# The Message-ID shape our DMARC / TLS-RPT reports go out under, and the
# edge-side check that spots it inside a bounce - the two halves of the
# report-bounce loop breaker.
class AggregateReportTest < Minitest::Test
  Report = MailOnRails::AggregateReport

  test "message_id builds the recognisable shape for both kinds" do
    assert_equal "<dmarc-report.1789344000.remote.test.1c9cc08ed6b9@example.test>",
                 Report.message_id("dmarc", "1789344000.remote.test.1c9cc08ed6b9", "example.test")
    assert_equal "<tlsrpt-report.1789344000.remote.test.1c9cc08ed6b9@example.test>",
                 Report.message_id("tlsrpt", "1789344000.remote.test.1c9cc08ed6b9", "example.test")
    assert_raises(ArgumentError) { Report.message_id("fbl", "x", "example.test") }
  end

  test "references? spots a report Message-ID however a bounce quotes it" do
    id = Report.message_id("dmarc", "1789344000.remote.test.1c9cc08ed6b9", "example.test")

    exchange_ndr = "From: postmaster@remote.test\r\nIn-Reply-To: #{id}\r\nSubject: Undeliverable\r\n\r\nfull\r\n"
    assert Report.references?(exchange_ndr)

    postfix_bounce = "From: MAILER-DAEMON@remote.test\r\n\r\nUndelivered Message\r\n\r\n" \
                     "Return-Path: <dmarc@example.test>\r\nMessage-ID: #{id}\r\nSubject: Report Domain\r\n"
    assert Report.references?(postfix_bounce)

    assert Report.references?("Message-Id: #{id.upcase}"), "case must not matter"
  end

  test "references? ignores ordinary mail and near misses" do
    assert_not Report.references?("From: a@b.test\r\nMessage-ID: <abc123@b.test>\r\n\r\nhi\r\n")
    assert_not Report.references?("Message-ID: <dmarc-report.@example.test>"), "an empty report id is not ours"
    assert_not Report.references?("Message-ID: <dmarc-report.x y@example.test>"), "whitespace breaks the shape"
    assert_not Report.references?("dmarc-report.1.remote.test.abc@example.test"), "brackets are part of the shape"
    assert_not Report.references?(nil)
    assert_not Report.references?("")
  end

  test "references? only scans the front of a large message" do
    id = Report.message_id("tlsrpt", "1.remote.test.abc", "example.test")
    padding = "x" * (Report::SCAN_LIMIT + 10)

    assert_not Report.references?(padding + id)
    assert Report.references?(id + padding)
    assert Report.references?("\xFF\xFEbinary #{id}".b), "invalid bytes must not raise"
  end
end
