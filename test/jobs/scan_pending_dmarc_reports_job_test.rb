require "test_helper"
require "mail_on_rails/clamav_scanner"
require_relative "../test_helpers/clamav_stub_helper"
require_relative "../test_helpers/dmarc_report_mail_helper"

# The catch-up path for reports that arrived while virus scanning was
# disabled (scan_status nil in a dmarc@ inbox): once clamav is back, they
# are scanned, then ingested if clean - never parsed unscanned. Infected
# ones are re-filed into Quarantine; an unavailable scanner leaves them
# pending for the next run.
class ScanPendingDmarcReportsJobTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper
  include ClamavStubHelper
  include DmarcReportMailHelper

  CLEAN = MailOnRails::ClamavScanner::Result.new(:clean, nil)
  INFECTED = MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test")
  UNAVAILABLE = MailOnRails::ClamavScanner::Result.new(:unavailable, nil)

  setup do
    @domain = Domain.create!(name: "example.test")
    @account = EmailAccount.find_by!(email: "dmarc@example.test")
    # As the mailroom stores it with scanning off: no scan_status, but the
    # rspamd sender verdict was still recorded at delivery time.
    @message = EmailMessage.deliver_raw(@account.inbox, report_mail(@account.email),
                                        auth_results: "mail.test; spf=pass; dkim=pass; dmarc=pass")
  end

  test "scans pending report mail, then ingests it" do
    perform_enqueued_jobs do
      with_scanner(enabled: true, scan: CLEAN) { ScanPendingDmarcReportsJob.perform_now }
    end

    assert_equal "clean", @message.reload.scan_status
    assert_equal 4, @domain.dmarc_reports.sum(:count)
  end

  test "an unverified sender is scanned but still not ingested" do
    @message.update!(auth_results: "mail.test; dmarc=fail")
    perform_enqueued_jobs do
      with_scanner(enabled: true, scan: CLEAN) { ScanPendingDmarcReportsJob.perform_now }
    end

    assert_equal "clean", @message.reload.scan_status
    assert_equal 0, DmarcReport.count
  end

  test "an infected pending report is quarantined, not parsed" do
    assert_no_enqueued_jobs only: IngestDmarcReportJob do
      with_scanner(enabled: true, scan: INFECTED) { ScanPendingDmarcReportsJob.perform_now }
    end

    @message.reload
    assert_equal Mailbox::QUARANTINE, @message.mailbox.name
    assert_equal "infected", @message.scan_status
    assert_equal "Eicar-Test", @message.virus_name
    assert_equal 0, DmarcReport.count
  end

  test "scanner disabled or unavailable leaves the message pending" do
    with_scanner(enabled: false) { ScanPendingDmarcReportsJob.perform_now }
    assert_nil @message.reload.scan_status

    with_scanner(enabled: true, scan: UNAVAILABLE) { ScanPendingDmarcReportsJob.perform_now }
    assert_nil @message.reload.scan_status
    assert_equal 0, DmarcReport.count
  end

  test "already-scanned and ordinary-inbox mail is untouched" do
    @message.update!(scan_status: "clean")
    other = EmailAccount.create!(email: "user@example.test", password: "pw-123456")
    pending_elsewhere = EmailMessage.deliver_raw(other.inbox, report_mail(other.email))

    calls = 0
    with_scanner(enabled: true, scan: ->(_raw) { calls += 1; CLEAN }) { ScanPendingDmarcReportsJob.perform_now }
    assert_equal 0, calls
    assert_nil pending_elsewhere.reload.scan_status
  end
end
