# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/deliver_smtp_outbound_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# Locally generated DSNs never rode the wire, so no SMTP edge or mailroom
# looked at them - DeliverSmtpOutboundJob#deliver_dsn stamps and scans them
# itself: authenticated_as the mailer-daemon From (so the UI shows the
# bounce as a verified local sender, not "unverified"), a real clamav
# verdict, Quarantine on a hit, fail-open "unscanned" on an outage.
class DeliverDsnScanTest < DbSuite::TestCase
  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "carol@example.test",
                                                   password: "a-long-test-password")
  end

  def inbox = account.mailboxes.find_by!(name: "INBOX")

  # Same hand-rolled singleton stub as ImapBackendTest: a nil result means
  # scanning is disabled; otherwise every scan returns the canned verdict.
  def with_scan_result(result)
    singleton = MailOnRails::ClamavScanner.singleton_class
    enabled = MailOnRails::ClamavScanner.method(:enabled?)
    scan = MailOnRails::ClamavScanner.method(:scan)
    singleton.define_method(:enabled?) { !result.nil? }
    singleton.define_method(:scan) { |_raw| result }
    yield
  ensure
    singleton.define_method(:enabled?, enabled)
    singleton.define_method(:scan, scan)
  end

  # An FBL-suppressed recipient makes the queue drainer bounce the row
  # without a network attempt - the cheapest way to run the real DSN path.
  def bounce_outbound(scan_result)
    account # create the sender before the run so deliver_dsn finds it
    MailOnRails::SuppressedRecipient.record_complaint!("complainer@remote.test")
    MailOnRails::SmtpOutboundMessage.create!(mail_from: "carol@example.test",
                                             recipient: "complainer@remote.test",
                                             data: "From: carol@example.test\r\n\r\nhi",
                                             next_attempt_at: Time.current)
    with_scan_result(scan_result) { MailOnRails::DeliverSmtpOutboundJob.new.perform }
  end

  test "a clean DSN lands in INBOX authenticated as the mailer-daemon sender" do
    bounce_outbound(MailOnRails::ClamavScanner::Result.new(:clean, nil))

    dsn = inbox.email_messages.sole
    assert_equal "mailer-daemon@example.test", dsn.authenticated_as
    assert_predicate dsn, :sender_verified?
    assert_equal "clean", dsn.scan_status
  end

  test "an infected DSN is quarantined with its verdict" do
    bounce_outbound(MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test"))

    assert_equal 0, inbox.email_messages.count
    dsn = account.quarantine_mailbox.email_messages.sole
    assert_equal "infected", dsn.scan_status
    assert_equal "Eicar-Test", dsn.virus_name
    assert_equal "mailer-daemon@example.test", dsn.authenticated_as
  end

  test "a scanner outage fails open as unscanned for the rescan job" do
    bounce_outbound(MailOnRails::ClamavScanner::Result.new(:unavailable, nil))

    dsn = inbox.email_messages.sole
    assert_equal "unscanned", dsn.scan_status
    assert_predicate dsn, :sender_verified?
  end

  test "with scanning disabled the DSN is delivered without a verdict" do
    bounce_outbound(nil)

    dsn = inbox.email_messages.sole
    assert_nil dsn.scan_status
    assert_predicate dsn, :sender_verified?
  end
end
