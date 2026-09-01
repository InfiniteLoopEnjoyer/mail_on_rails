# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ingest_fbl_report_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ingest_dmarc_report_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ingest_tls_rpt_report_job", __dir__)

# The reporter-allowlist gate (BaseJob#report_reporter_untrusted_reason)
# shared by every report ingest job: fbl@, dmarc@ and tls-rpt@. A report
# is acted on only when it passed DMARC AND its From: domain is on
# report_reporter_allowlist (suffix match); otherwise the mail is kept and
# the automated action is skipped. Bounce and unsubscribe are gated by a
# signed VERP return-path / token instead and are not covered here.
class ReportReporterAllowlistTest < DbSuite::TestCase
  Message = Struct.new(:from_address, :dmarc) do
    def auth_result(mechanism) = mechanism == "dmarc" ? dmarc : nil
  end

  # All three ingest jobs inherit the same gate; exercise each so a future
  # divergence is caught.
  JOBS = [ MailOnRails::IngestFblReportJob,
           MailOnRails::IngestDmarcReportJob,
           MailOnRails::IngestTlsRptReportJob ].freeze

  def teardown
    MailOnRails::Settings.reset!
  end

  def reason(job_class, from_address, dmarc)
    job_class.new.send(:report_reporter_untrusted_reason, Message.new(from_address, dmarc))
  end

  test "a DMARC-passing allowlisted reporter is trusted by every report job" do
    MailOnRails::Settings.overrides = { report_reporter_allowlist: [ "provider.test" ] }
    JOBS.each do |job|
      assert_nil reason(job, "feedback@provider.test", "pass"), "#{job} must trust the reporter"
    end
  end

  test "a report that did not pass DMARC is untrusted regardless of domain" do
    MailOnRails::Settings.overrides = { report_reporter_allowlist: [ "provider.test" ] }
    JOBS.each do |job|
      assert_match(/DMARC/, reason(job, "feedback@provider.test", "fail").to_s)
      assert_match(/DMARC/, reason(job, "feedback@provider.test", nil).to_s)
    end
  end

  test "a DMARC pass from an un-allowlisted domain is untrusted" do
    MailOnRails::Settings.overrides = { report_reporter_allowlist: [ "provider.test" ] }
    JOBS.each do |job|
      assert_match(/allowlist/, reason(job, "feedback@evil.test", "pass").to_s)
    end
  end

  test "matching is suffix-wise so a subdomain of a listed domain is trusted" do
    MailOnRails::Settings.overrides = { report_reporter_allowlist: [ "provider.test" ] }
    assert_nil reason(MailOnRails::IngestDmarcReportJob, "dmarc@mx.reports.provider.test", "pass")
    # ...but a domain that merely ends in the same text is not a subdomain.
    assert_match(/allowlist/, reason(MailOnRails::IngestDmarcReportJob, "x@notprovider.test", "pass").to_s)
  end

  test "an empty allowlist trusts no reporter" do
    MailOnRails::Settings.overrides = { report_reporter_allowlist: [] }
    assert_match(/allowlist/, reason(MailOnRails::IngestFblReportJob, "feedback@provider.test", "pass").to_s)
  end

  test "the seeded default trusts the major providers and no one else" do
    MailOnRails::Settings.reset!
    assert_nil reason(MailOnRails::IngestDmarcReportJob, "noreply-dmarc-support@google.com", "pass")
    assert_nil reason(MailOnRails::IngestFblReportJob, "staff@hotmail.com", "pass")
    assert_match(/allowlist/, reason(MailOnRails::IngestFblReportJob, "feedback@provider.test", "pass").to_s)
  end
end
