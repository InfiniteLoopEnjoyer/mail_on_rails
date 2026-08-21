# frozen_string_literal: true

require "test_helper"
require "active_job"
require "zlib"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/send_dmarc_reports_job", __dir__)
require "fake_resolver"
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# The sending side of the DMARC feedback loop: DmarcAggregateEvent rows
# written by the edge roll up into RFC 7489 aggregate XML reports, queued
# to the rua= addresses a policy domain published - with the RFC 7489 7.1
# external-destination authorization check.
class DmarcReportingTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    MailOnRails::Domain.create!(name: "example.test")
  end

  def record_event(occurred_at: nil, **overrides)
    event = MailOnRails::DmarcAggregateEvent.record!(**{
      policy_domain: "remote.test", from_domain: "remote.test",
      source_ip: "203.0.113.9", envelope_from: "bulk@remote.test",
      disposition: "reject", dkim_aligned: false, spf_aligned: false,
      spf_result: "fail", spf_domain: "remote.test", dkim_results: "remote.test=fail",
      policy_p: "reject", policy_adkim: "r", policy_aspf: "r", policy_pct: 100
    }.merge(overrides))
    event.update!(occurred_at: occurred_at) if occurred_at
    event
  end

  def run_job(txt_records, date: Date.yesterday)
    job = MailOnRails::SendDmarcReportsJob.new
    fake = FakeResolver.new(txt: txt_records)
    job.define_singleton_method(:dns) { fake }
    job.perform(date)
  end

  def report_xml(message)
    mail = Mail.read_from_string(message.data)
    attachment = mail.attachments.first
    Zlib.gunzip(attachment.body.decoded)
  end

  test "record! clamps hostile input and prune! enforces retention" do
    event = record_event(disposition: "bogus", override_reason: "x" * 500)
    assert_equal "none", event.disposition, "an unknown disposition must clamp to none"
    assert_operator event.override_reason.length, :<=, 200

    event.update!(occurred_at: 8.days.ago)
    MailOnRails::DmarcAggregateEvent.prune!
    assert_equal 0, MailOnRails::DmarcAggregateEvent.count
  end

  test "record! never raises" do
    # nil inputs and a broken table alike come back as a logged nil/row,
    # never an exception on the acceptance path.
    assert MailOnRails::DmarcAggregateEvent.record!(policy_domain: nil, disposition: "none")

    singleton = MailOnRails::DmarcAggregateEvent.singleton_class
    original = MailOnRails::DmarcAggregateEvent.method(:create!)
    singleton.define_method(:create!) { |**| raise ActiveRecord::StatementInvalid, "table gone" }
    begin
      assert_nil MailOnRails::DmarcAggregateEvent.record!(policy_domain: "x.test", disposition: "none")
    ensure
      singleton.define_method(:create!, original)
    end
  end

  test "queues one gzip XML report per rua address, rows collapsed by count" do
    2.times { record_event(occurred_at: Date.yesterday.noon) }
    record_event(occurred_at: Date.yesterday.noon, source_ip: "198.51.100.7",
                 disposition: "none", override_reason: "p=reject not enforced (local policy)")
    MailOnRails::DmarcAggregateEvent.update_all(occurred_at: Date.yesterday.noon)

    run_job({ "_dmarc.remote.test" => [ "v=DMARC1; p=reject; rua=mailto:reports@remote.test" ] })

    message = MailOnRails::SmtpOutboundMessage.last
    refute_nil message, "a report must be queued"
    assert_equal "reports@remote.test", message.recipient
    assert_equal "dmarc@example.test", message.mail_from
    assert_match(/Report Domain: remote\.test Submitter: example\.test/, message.data)

    xml = report_xml(message)
    assert_match(%r{<domain>remote\.test</domain>}, xml)
    assert_match(%r{<p>reject</p>}, xml)
    assert_match(%r{<source_ip>203\.0\.113\.9</source_ip>\s*<count>2</count>}m, xml)
    assert_match(%r{<source_ip>198\.51\.100\.7</source_ip>\s*<count>1</count>}m, xml)
    assert_match(%r{<disposition>reject</disposition>}, xml)
    assert_match(%r{<reason><type>local_policy</type><comment>p=reject not enforced \(local policy\)</comment></reason>}, xml)
    assert_match(%r{<dkim><domain>remote\.test</domain><result>fail</result></dkim>}, xml)
    assert_match(%r{<spf><domain>remote\.test</domain><result>fail</result></spf>}, xml)
    assert_match(%r{<header_from>remote\.test</header_from>}, xml)
    assert_match(%r{<envelope_from>remote\.test</envelope_from>}, xml)
  end

  test "no rua or no DMARC record queues nothing" do
    record_event(occurred_at: Date.yesterday.noon)

    run_job({ "_dmarc.remote.test" => [ "v=DMARC1; p=reject" ] })
    run_job({})

    assert_equal 0, MailOnRails::SmtpOutboundMessage.count
  end

  test "external rua destination requires the RFC 7489 authorization record" do
    record_event(occurred_at: Date.yesterday.noon)
    rua = [ "v=DMARC1; p=reject; rua=mailto:agg@thirdparty.test" ]

    run_job({ "_dmarc.remote.test" => rua })
    assert_equal 0, MailOnRails::SmtpOutboundMessage.count,
                 "an unauthorized external destination must be skipped"

    run_job({ "_dmarc.remote.test" => rua,
              "remote.test._report._dmarc.thirdparty.test" => [ "v=DMARC1" ] })
    assert_equal "agg@thirdparty.test", MailOnRails::SmtpOutboundMessage.last&.recipient
  end

  test "rua size suffixes are stripped and the opt-out setting disables the job" do
    record_event(occurred_at: Date.yesterday.noon)

    run_job({ "_dmarc.remote.test" => [ "v=DMARC1; p=reject; rua=mailto:reports@remote.test!10m" ] })
    assert_equal "reports@remote.test", MailOnRails::SmtpOutboundMessage.last&.recipient

    MailOnRails::SmtpOutboundMessage.delete_all
    MailOnRails::Settings.overrides = { smtp_dmarc_reports: false }
    run_job({ "_dmarc.remote.test" => [ "v=DMARC1; p=reject; rua=mailto:reports@remote.test" ] })
    assert_equal 0, MailOnRails::SmtpOutboundMessage.count
  ensure
    MailOnRails::Settings.reset!
  end
end
