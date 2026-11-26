# frozen_string_literal: true

require "test_helper"
require "active_job"
require "zlib"
require "json"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/aggregate_report_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/send_tls_rpt_reports_job", __dir__)
require "fake_resolver"
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# The sending side of TLS-RPT: TlsRptEvent rows written by the deliverer
# roll up into RFC 8460 JSON reports, queued to the rua= addresses a
# recipient domain published - sharing the DMARC job's Sent copy,
# Message-ID shape and bounce cooldown (AggregateReportJob).
class TlsRptReportingTest < DbSuite::TestCase
  TLSRPT = { "_smtp._tls.remote.test" => [ "v=TLSRPTv1; rua=mailto:tls@remote.test" ] }.freeze

  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    MailOnRails::Domain.create!(name: "example.test")
  end

  def record_event(**overrides)
    event = MailOnRails::TlsRptEvent.record!(**{ policy_domain: "remote.test", policy_type: "sts",
                                                 mx: "mx.remote.test" }.merge(overrides))
    event.update!(occurred_at: Date.yesterday.noon)
    event
  end

  def run_job(txt_records = TLSRPT)
    job = MailOnRails::SendTlsRptReportsJob.new
    fake = FakeResolver.new(txt: txt_records)
    job.define_singleton_method(:dns) { fake }
    job.perform(Date.yesterday)
  end

  test "queues one gzip JSON report per rua address, addressed and filed in tls-rpt@'s Sent folder" do
    record_event
    record_event(result_type: "certificate-expired", detail: "notAfter 2026-01-01")

    run_job

    message = MailOnRails::SmtpOutboundMessage.sole
    assert_equal "tls@remote.test", message.recipient
    assert_equal "tls-rpt@example.test", message.mail_from
    assert message.aggregate_report?

    mail = Mail.read_from_string(message.data)
    assert_equal [ "tls@remote.test" ], mail.to
    assert_match(/\Atlsrpt-report\.\d+\.remote\.test\.\h{12}@example\.test\z/, mail.message_id)
    assert_equal "No", mail.header["TLS-Required"]&.value
    assert_equal "remote.test", mail.header["TLS-Report-Domain"]&.value

    report = JSON.parse(Zlib.gunzip(mail.attachments.first.body.decoded))
    assert_equal "example.test", report["organization-name"]
    assert_match(/@example\.test\z/, report["report-id"])
    policy = report["policies"].sole
    assert_equal 1, policy["summary"]["total-successful-session-count"]
    assert_equal 1, policy["summary"]["total-failure-session-count"]
    assert_equal "certificate-expired", policy["failure-details"].sole["result-type"]

    sent = MailOnRails::EmailAccount.find_by!(email: "tls-rpt@example.test").find_mailbox("Sent")
    assert_equal message.data, sent.email_messages.sole.raw
  end

  test "a rua address at a hosted domain is skipped: we never report to ourselves" do
    record_event(policy_domain: "example.test", mx: "mx.example.test", result_type: "certificate-expired")

    run_job({ "_smtp._tls.example.test" => [ "v=TLSRPTv1; rua=mailto:tls-rpt@example.test,mailto:tls@thirdparty.test" ] })

    assert_equal [ "tls@thirdparty.test" ], MailOnRails::SmtpOutboundMessage.pluck(:recipient)
  end

  # The deliverer end of the loop breaker (AggregateReport): handing a
  # report to its destination is a TLS session with that destination, and
  # counting it would put the destination in tomorrow's run, forever.
  class MxResolver < FakeResolver
    def initialize = super(a: { "mx.remote.test" => [ "93.184.216.34" ] })
    def mx_answer(_name) = MailOnRails::SenderAuth::Dns::Answer.new(records: [ [ 10, "mx.remote.test" ] ], secure: false)
  end

  def deliverer(&send_via)
    MailOnRails::Settings.overrides = { mta_sts: false }
    deliverer = MailOnRails::OutboundDeliverer.new(dns: MxResolver.new)
    deliverer.define_singleton_method(:send_via) { |*, **| send_via.call }
    deliverer
  end

  def queue(mail_from)
    MailOnRails::SmtpOutboundMessage.create!(mail_from: mail_from, recipient: "rua@remote.test",
                                             data: "From: #{mail_from}\r\n\r\nhi", next_attempt_at: Time.current)
  end

  test "delivering one of our own reports records no TLS-RPT event, success or failure" do
    delivered = deliverer { :delivered }
    assert_equal :delivered, delivered.deliver(queue("tls-rpt@example.test"))
    assert_equal :delivered, delivered.deliver(queue("dmarc@example.test"))

    failing = deliverer { raise OpenSSL::SSL::SSLError, "certificate verify failed" }
    assert_raises(MailOnRails::OutboundDeliverer::TransientError) { failing.deliver(queue("tls-rpt@example.test")) }

    assert_equal 0, MailOnRails::TlsRptEvent.count
  ensure
    MailOnRails::Settings.reset!
  end

  test "ordinary mail still records its session, also right after a report on the same deliverer" do
    deliverer = deliverer { :delivered }
    deliverer.deliver(queue("dmarc@example.test"))
    deliverer.deliver(queue("user@example.test"))
    # Only a hosted domain's report account counts: this one is a stranger's.
    deliverer.deliver(queue("dmarc@elsewhere.test"))

    assert_equal [ "remote.test", "remote.test" ], MailOnRails::TlsRptEvent.pluck(:policy_domain)
    assert_equal [ "no-policy-found" ], MailOnRails::TlsRptEvent.distinct.pluck(:policy_type)
  ensure
    MailOnRails::Settings.reset!
  end

  test "the report mailboxes the edge exempts are the ones every domain is given" do
    assert_equal [ MailOnRails::Domain::DMARC_LOCAL_PART, MailOnRails::Domain::TLS_RPT_LOCAL_PART ],
                 MailOnRails::AggregateReport::MAILBOX_LOCAL_PARTS
  end

  test "no TLSRPT record queues nothing" do
    record_event

    run_job({})

    assert_equal 0, MailOnRails::SmtpOutboundMessage.count
  end

  test "a rua address that bounced a report is skipped for the cooldown, independently of dmarc@'s" do
    record_event
    MailOnRails::SuppressedRecipient.record_bounce!("tls@remote.test", sender: "tls-rpt@example.test")
    MailOnRails::SuppressedRecipient.record_bounce!("tls@remote.test", sender: "dmarc@example.test")

    run_job
    assert_equal 0, MailOnRails::SmtpOutboundMessage.count

    MailOnRails::SuppressedRecipient.update_all(last_complaint_at: MailOnRails::AggregateReportJob::BOUNCE_COOLDOWN.ago - 1.hour)
    run_job
    assert_equal "tls@remote.test", MailOnRails::SmtpOutboundMessage.sole.recipient
    assert MailOnRails::SuppressedRecipient.suppressed?("tls@remote.test", sender: "dmarc@example.test"),
           "the job only expires its own sender's bounce rows"
  end
end
