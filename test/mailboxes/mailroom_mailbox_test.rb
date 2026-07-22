require "test_helper"
require "mail_on_rails/clamav_scanner"
require_relative "../test_helpers/clamav_stub_helper"

# Inbound routing with the virus policy: the daemon's trusted
# X-MailOnRails-Scan stamp decides; stampless mail falls back to a local
# scan when configured; anything not clean lands in Quarantine (deduped by
# Message-ID, because 451 tempfails make senders retry the same message),
# and a clean delivery sweeps stale "unscanned" review copies.
class MailroomMailboxTest < ActionMailbox::TestCase
  include ClamavStubHelper

  EMAIL = "user@example.test"

  setup do
    @account = EmailAccount.create!(email: EMAIL, password: "pw-123456")
  end

  # A daemon-stamped inbound message, as IngressClient#stamp emits it.
  def source(scan: nil, virus: nil, message_id: "<mid-1@remote.test>", subject: "hi")
    headers = [ "Return-Path: <sender@remote.test>",
                "X-Original-To: #{EMAIL}",
                "X-MailOnRails-Authenticated: no" ]
    headers << "X-MailOnRails-Scan: #{scan}" if scan
    headers << "X-MailOnRails-Virus: #{virus}" if virus
    headers += [ "Message-ID: #{message_id}",
                 "From: sender@remote.test",
                 "To: #{EMAIL}",
                 "Subject: #{subject}" ]
    headers.join("\r\n") + "\r\n\r\nbody\r\n"
  end

  def quarantine
    @account.find_mailbox(Mailbox::QUARANTINE)
  end

  def refuse_local_scans(&block)
    with_scanner(enabled: true, scan: ->(*) { raise "the mailroom must trust the stamp, not rescan" }, &block)
  end

  test "clean-stamped mail goes to INBOX without a local rescan" do
    refuse_local_scans do
      receive_inbound_email_from_source(source(scan: "clean"))
    end

    message = @account.inbox.email_messages.sole
    assert_equal "clean", message.scan_status
    assert_nil quarantine, "no quarantine mailbox should be created for clean mail"
  end

  test "infected-stamped mail is quarantined with its virus name, INBOX untouched" do
    refuse_local_scans do
      receive_inbound_email_from_source(source(scan: "infected", virus: "Eicar-Test-Signature"))
    end

    assert_empty @account.inbox.email_messages
    message = quarantine.email_messages.sole
    assert_equal "infected", message.scan_status
    assert_equal "Eicar-Test-Signature", message.virus_name
  end

  # Byte-identical retries are already deduped by Action Mailbox's
  # message_id+checksum index at the ingress; the mailroom dedup covers
  # retries whose stamped bytes differ (e.g. auth_results varies per
  # attempt) but which are the same message by Message-ID.
  test "retry-duplicated unscanned copies dedup by Message-ID" do
    2.times { |i| receive_inbound_email_from_source(source(scan: "unscanned", subject: "attempt #{i}")) }

    assert_equal 1, quarantine.email_messages.count
    assert_equal "unscanned", quarantine.email_messages.sole.scan_status
  end

  test "a clean delivery sweeps stale unscanned copies but never infected ones" do
    receive_inbound_email_from_source(source(scan: "unscanned"))
    receive_inbound_email_from_source(source(scan: "infected", virus: "Sig", message_id: "<other@remote.test>"))
    assert_equal 2, quarantine.email_messages.count

    receive_inbound_email_from_source(source(scan: "clean"))

    assert_equal 1, @account.inbox.email_messages.count
    remaining = quarantine.email_messages.sole
    assert_equal "infected", remaining.scan_status, "the sweep must only remove unscanned rows"
  end

  test "stampless mail is scanned locally when configured" do
    with_scanner(enabled: true, scan: MailOnRails::ClamavScanner::Result.new(:infected, "Local-Sig")) do
      receive_inbound_email_from_source(source)
    end

    assert_empty @account.inbox.email_messages
    message = quarantine.email_messages.sole
    assert_equal "infected", message.scan_status
    assert_equal "Local-Sig", message.virus_name
  end

  test "a local scanner outage quarantines the message as unscanned" do
    with_scanner(enabled: true, scan: MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      receive_inbound_email_from_source(source)
    end

    assert_empty @account.inbox.email_messages
    assert_equal "unscanned", quarantine.email_messages.sole.scan_status
  end

  test "no stamp and no scanner means plain INBOX delivery" do
    receive_inbound_email_from_source(source)

    message = @account.inbox.email_messages.sole
    assert_nil message.scan_status
    assert_nil quarantine
  end
end
