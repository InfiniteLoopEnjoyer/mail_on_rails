require "test_helper"
require "mail_on_rails/clamav_scanner"
require "mail_on_rails/rspamd_analyzer"
require_relative "../test_helpers/clamav_stub_helper"
require_relative "../test_helpers/rspamd_stub_helper"
require_relative "../test_helpers/dmarc_report_mail_helper"

# Mail delivered to a domain's dmarc@ ingestion account is parsed for
# aggregate reports - but only after a clamav scan came back clean AND
# the report mail's sender verified (it passed DMARC itself, or was an
# authenticated local submission). Infected mail is quarantined and never
# parsed; with scanning disabled the report is delivered but left
# unparsed (ScanPendingDmarcReportsJob catches up later). Ordinary
# accounts never trigger ingestion.
class DmarcIngestionTest < ActionMailbox::TestCase
  include ActiveJob::TestHelper
  include ClamavStubHelper
  include RspamdStubHelper
  include DmarcReportMailHelper

  CLEAN = MailOnRails::ClamavScanner::Result.new(:clean, nil)
  INFECTED = MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test")

  setup do
    @domain = Domain.create!(name: "example.test")
    @dmarc_account = EmailAccount.find_by!(email: "dmarc@example.test")
  end

  def rspamd_verdict(dmarc:)
    MailOnRails::RspamdAnalyzer::Result.new(
      status: :ok, action: "no action", score: 0.1, required_score: 6.0,
      spf: "pass", dkim: "pass", dmarc: dmarc,
      auth_results: "mail.test; spf=pass; dkim=pass; dmarc=#{dmarc}"
    )
  end

  def receive_report(to: "dmarc@example.test", dmarc: "pass", &block)
    block ||= -> { receive_inbound_email_from_source(report_mail(to)) }
    with_scanner(enabled: true, scan: CLEAN) do
      with_rspamd(enabled: true, analyze: rspamd_verdict(dmarc: dmarc), &block)
    end
  end

  test "a scanned-clean report from a DMARC-passing sender is ingested" do
    perform_enqueued_jobs { receive_report }

    assert_equal 1, @dmarc_account.inbox.email_messages.count
    assert_equal 4, @domain.dmarc_reports.sum(:count)
  end

  test "a report whose own mail fails DMARC is delivered but never parsed" do
    perform_enqueued_jobs { receive_report(dmarc: "fail") }

    assert_equal 1, @dmarc_account.inbox.email_messages.count
    assert_equal 0, DmarcReport.count
  end

  test "with rspamd off the sender cannot verify, so nothing is parsed" do
    perform_enqueued_jobs do
      with_scanner(enabled: true, scan: CLEAN) do
        receive_inbound_email_from_source(report_mail("dmarc@example.test"))
      end
    end
    assert_equal 1, @dmarc_account.inbox.email_messages.count
    assert_equal 0, DmarcReport.count
  end

  test "with scanning disabled the report is delivered but not enqueued" do
    assert_no_enqueued_jobs only: IngestDmarcReportJob do
      with_rspamd(enabled: true, analyze: rspamd_verdict(dmarc: "pass")) do
        receive_inbound_email_from_source(report_mail("dmarc@example.test"))
      end
    end
    assert_equal 1, @dmarc_account.inbox.email_messages.count
    assert_equal 0, DmarcReport.count
  end

  test "an infected report is quarantined and never parsed" do
    assert_no_enqueued_jobs only: IngestDmarcReportJob do
      with_scanner(enabled: true, scan: INFECTED) do
        receive_inbound_email_from_source(report_mail("dmarc@example.test"))
      end
    end
    assert_equal 0, @dmarc_account.inbox.email_messages.count
    assert_equal 0, DmarcReport.count
  end

  test "a report rspamd calls spam is filed to Junk and never parsed" do
    spam = MailOnRails::RspamdAnalyzer::Result.new(
      status: :ok, action: "add header", score: 8.4, required_score: 6.0,
      spf: "pass", dkim: "pass", dmarc: "pass", auth_results: "mail.test; spf=pass; dkim=pass; dmarc=pass"
    )
    assert_no_enqueued_jobs only: IngestDmarcReportJob do
      with_scanner(enabled: true, scan: CLEAN) do
        with_rspamd(enabled: true, analyze: spam) { receive_inbound_email_from_source(report_mail("dmarc@example.test")) }
      end
    end
    assert_equal 0, @dmarc_account.inbox.email_messages.count
    assert_equal 1, @dmarc_account.find_mailbox("Junk").email_messages.count
    assert_equal 0, DmarcReport.count
  end

  test "mail to an ordinary account never triggers ingestion" do
    EmailAccount.create!(email: "user@example.test", password: "pw-123456")
    assert_no_enqueued_jobs only: IngestDmarcReportJob do
      receive_report(to: "user@example.test") { receive_inbound_email_from_source(report_mail("user@example.test")) }
    end
    assert_equal 0, DmarcReport.count
  end

  test "a non-report mailed to dmarc@ delivers without creating rows" do
    source = "Return-Path: <someone@remote.test>\r\n" \
             "X-Original-To: dmarc@example.test\r\n" \
             "X-MailOnRails-Authenticated: no\r\n" \
             "From: someone@remote.test\r\nTo: dmarc@example.test\r\n" \
             "Subject: hello\r\n\r\njust text\r\n"
    perform_enqueued_jobs do
      receive_report { receive_inbound_email_from_source(source) }
    end
    assert_equal 1, @dmarc_account.inbox.email_messages.count
    assert_equal 0, DmarcReport.count
  end
end
