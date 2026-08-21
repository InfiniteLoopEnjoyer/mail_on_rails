# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ingest_fbl_report_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/deliver_smtp_outbound_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# The complaint feedback-loop pipeline: an ARF report landing in fbl@
# (IngestFblReportJob) suppresses the complainant, and the outbound
# drainer (DeliverSmtpOutboundJob) then bounces queued mail to them
# instead of attempting delivery.
class FblSuppressionTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
  end

  # An ARF report shaped like RFC 5965's example: feedback-report part
  # with Original-Rcpt-To, original message attached.
  ARF_WITH_RCPT_TO = <<~ARF
    From: <feedback@provider.test>
    To: <fbl@example.test>
    Subject: FW: complaint
    MIME-Version: 1.0
    Content-Type: multipart/report; report-type=feedback-report; boundary="part"

    --part
    Content-Type: text/plain; charset="US-ASCII"

    This is an email abuse report.
    --part
    Content-Type: message/feedback-report

    Feedback-Type: abuse
    User-Agent: SomeGenerator/1.0
    Version: 1
    Original-Mail-From: <sender@example.test>
    Original-Rcpt-To: Complainer@remote.test
    Received-Date: Thu, 8 Mar 2005 14:00:00 EDT

    --part
    Content-Type: message/rfc822

    From: <sender@example.test>
    To: <complainer@remote.test>
    Subject: original message
    Message-ID: <original@example.test>

    original body
    --part--
  ARF

  # Microsoft's JMRP shape: no Original-Rcpt-To; the recipient is the
  # X-HmXmrOriginalRecipient header stamped on the attached original.
  ARF_JMRP_STYLE = <<~ARF
    From: <staff@hotmail.test>
    To: <jmrp@example.test>
    Subject: complaint about message from 192.0.2.1
    MIME-Version: 1.0
    Content-Type: multipart/report; report-type=feedback-report; boundary="part"

    --part
    Content-Type: text/plain; charset="US-ASCII"

    An email abuse report from a Windows Live Hotmail user.
    --part
    Content-Type: message/feedback-report

    Feedback-Type: abuse
    User-Agent: JMRP/2.0
    Version: 1
    Source-IP: 192.0.2.1

    --part
    Content-Type: message/rfc822

    X-HmXmrOriginalRecipient: <someone@hotmail.test>
    From: <sender@example.test>
    To: undisclosed-recipients:;
    Subject: original message

    original body
    --part--
  ARF

  test "parses an ARF report via Original-Rcpt-To" do
    report = MailOnRails::FblReportParser.parse(ARF_WITH_RCPT_TO)

    assert report
    assert_equal "abuse", report.feedback_type
    assert_equal "SomeGenerator/1.0", report.user_agent
    assert_equal [ "complainer@remote.test" ], report.complainants
  end

  test "parses a JMRP-style report via X-HmXmrOriginalRecipient" do
    report = MailOnRails::FblReportParser.parse(ARF_JMRP_STYLE)

    assert report
    assert_equal [ "someone@hotmail.test" ], report.complainants
  end

  test "falls back to the attached original's To addresses" do
    arf = ARF_JMRP_STYLE.sub("X-HmXmrOriginalRecipient: <someone@hotmail.test>\n", "")
                        .sub("To: undisclosed-recipients:;", "To: fallback@remote.test")
    report = MailOnRails::FblReportParser.parse(arf)

    assert report
    assert_equal [ "fallback@remote.test" ], report.complainants
  end

  test "non-ARF mail and unusable addresses parse to nil" do
    assert_nil MailOnRails::FblReportParser.parse("From: a@b.test\nSubject: hi\n\nnot a report\n")
    assert_nil MailOnRails::FblReportParser.parse(ARF_WITH_RCPT_TO.sub("Complainer@remote.test", "not-an-address"))
    assert_nil MailOnRails::FblReportParser.parse("")
  end

  test "complainant count is capped" do
    rcpts = (1..50).map { |i| "Original-Rcpt-To: user#{i}@remote.test" }.join("\n")
    arf = ARF_WITH_RCPT_TO.sub("Original-Rcpt-To: Complainer@remote.test", rcpts)
    report = MailOnRails::FblReportParser.parse(arf)

    assert_equal MailOnRails::FblReportParser::MAX_COMPLAINANTS, report.complainants.size
  end

  test "record_complaint! upserts and suppressed? normalizes" do
    first = MailOnRails::SuppressedRecipient.record_complaint!("user@remote.test", feedback_type: "abuse",
                                                                                  reporter: "JMRP/2.0")
    again = MailOnRails::SuppressedRecipient.record_complaint!("user@remote.test")

    assert_equal first, again
    assert_equal 2, again.reload.complaints_count
    assert_equal "abuse", again.feedback_type, "repeat without metadata keeps the recorded values"
    assert MailOnRails::SuppressedRecipient.suppressed?("  User@Remote.test ")
    assert_not MailOnRails::SuppressedRecipient.suppressed?("other@remote.test")
  end

  test "ingest job suppresses complainants only from verified senders" do
    message = Struct.new(:id, :raw, :from_address) do
      def sender_verified? = false
    end.new(1, ARF_WITH_RCPT_TO, "feedback@provider.test")
    MailOnRails::IngestFblReportJob.new.perform(message)
    assert_not MailOnRails::SuppressedRecipient.suppressed?("complainer@remote.test"),
               "an unverified report must not suppress anyone"

    verified = Struct.new(:id, :raw, :from_address) do
      def sender_verified? = true
    end.new(2, ARF_WITH_RCPT_TO, "feedback@provider.test")
    MailOnRails::IngestFblReportJob.new.perform(verified)
    assert MailOnRails::SuppressedRecipient.suppressed?("complainer@remote.test")
  end

  test "ingest job never suppresses a hosted-domain address" do
    MailOnRails::Domain.create!(name: "remote.test")
    message = Struct.new(:id, :raw, :from_address) do
      def sender_verified? = true
    end.new(3, ARF_WITH_RCPT_TO, "feedback@provider.test")

    MailOnRails::IngestFblReportJob.new.perform(message)

    assert_not MailOnRails::SuppressedRecipient.suppressed?("complainer@remote.test")
  end

  test "outbound delivery to a suppressed recipient fails permanently without a network attempt" do
    MailOnRails::SuppressedRecipient.record_complaint!("complainer@remote.test")
    message = MailOnRails::SmtpOutboundMessage.create!(mail_from: "sender@example.test",
                                                       recipient: "complainer@remote.test",
                                                       data: "From: sender@example.test\r\n\r\nhi",
                                                       next_attempt_at: Time.current)

    MailOnRails::DeliverSmtpOutboundJob.new.perform

    assert_predicate message.reload, :failed?
    assert_match(/suppressed/, message.last_error)
  end
end
