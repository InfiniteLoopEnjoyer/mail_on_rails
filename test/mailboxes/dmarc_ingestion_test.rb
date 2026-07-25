require "test_helper"
require "mail_on_rails/clamav_scanner"
require_relative "../test_helpers/clamav_stub_helper"

# Mail delivered to a domain's dmarc@ ingestion account is parsed for
# aggregate reports - but only after a clamav scan came back clean.
# Infected mail is quarantined and never parsed; with scanning disabled
# the report is delivered but deliberately left unparsed. Ordinary
# accounts never trigger ingestion.
class DmarcIngestionTest < ActionMailbox::TestCase
  include ActiveJob::TestHelper
  include ClamavStubHelper

  CLEAN = MailOnRails::ClamavScanner::Result.new(:clean, nil)
  INFECTED = MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test")

  setup do
    @domain = Domain.create!(name: "example.test")
    @dmarc_account = EmailAccount.find_by!(email: "dmarc@example.test")
  end

  REPORT_XML = <<~XML.freeze
    <?xml version="1.0"?>
    <feedback>
      <report_metadata>
        <org_name>google.com</org_name>
        <report_id>rid-1</report_id>
        <date_range><begin>1753142400</begin><end>1753228800</end></date_range>
      </report_metadata>
      <policy_published><domain>example.test</domain></policy_published>
      <record>
        <row>
          <source_ip>198.51.100.10</source_ip>
          <count>4</count>
          <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
        </row>
      </record>
    </feedback>
  XML

  def report_mail(to)
    mail = Mail.new
    mail.from = "noreply-dmarc-support@google.com"
    mail.to = to
    mail.subject = "Report domain: example.test"
    mail.body = "attached"
    mail.add_file filename: "google.com!example.test!1!2.xml", content: REPORT_XML
    headers = "Return-Path: <noreply-dmarc-support@google.com>\r\n" \
              "X-Original-To: #{to}\r\n" \
              "X-MailOnRails-Authenticated: no\r\n"
    headers + mail.to_s
  end

  test "a scanned-clean report mailed to dmarc@ is delivered and ingested" do
    perform_enqueued_jobs do
      with_scanner(enabled: true, scan: CLEAN) do
        receive_inbound_email_from_source(report_mail("dmarc@example.test"))
      end
    end

    assert_equal 1, @dmarc_account.inbox.email_messages.count
    assert_equal 4, @domain.dmarc_reports.sum(:count)
  end

  test "with scanning disabled the report is delivered but never parsed" do
    assert_no_enqueued_jobs only: IngestDmarcReportJob do
      receive_inbound_email_from_source(report_mail("dmarc@example.test"))
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

  test "mail to an ordinary account never triggers ingestion" do
    EmailAccount.create!(email: "user@example.test", password: "pw-123456")
    assert_no_enqueued_jobs only: IngestDmarcReportJob do
      with_scanner(enabled: true, scan: CLEAN) do
        receive_inbound_email_from_source(report_mail("user@example.test"))
      end
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
      with_scanner(enabled: true, scan: CLEAN) do
        receive_inbound_email_from_source(source)
      end
    end
    assert_equal 1, @dmarc_account.inbox.email_messages.count
    assert_equal 0, DmarcReport.count
  end
end
