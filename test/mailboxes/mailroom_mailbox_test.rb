require "test_helper"
require "mail_on_rails/clamav_scanner"
require "mail_on_rails/rspamd_analyzer"
require_relative "../test_helpers/clamav_stub_helper"
require_relative "../test_helpers/rspamd_stub_helper"

# Inbound routing and the trust boundary. The exim edge stamps the connection
# facts (Return-Path / X-Original-To / X-MailOnRails-Authenticated / -Client-Ip
# / -Helo) and strips forgeries; this app trusts those but recomputes every
# *verdict* itself - it never trusts an inbound X-MailOnRails-Auth-Results /
# -Scan / -Virus header, which the edge doesn't produce and a sender could only
# forge. So every inbound message is clamav-scanned (not clean -> Quarantine,
# deduped by Message-ID) and rspamd-analyzed (except authenticated submitters).
class MailroomMailboxTest < ActionMailbox::TestCase
  include ClamavStubHelper
  include RspamdStubHelper

  EMAIL = "user@example.test"

  CLEAN = MailOnRails::ClamavScanner::Result.new(:clean, nil)
  UNAVAILABLE = MailOnRails::ClamavScanner::Result.new(:unavailable, nil)

  setup do
    @account = EmailAccount.create!(email: EMAIL, password: "pw-123456")
  end

  # An exim-stamped inbound message, as bin/rails-ingress emits it. The
  # scan/virus/auth_results kwargs stamp *forged* verdict headers (what a
  # sender might smuggle past a broken edge) so tests can prove they're ignored.
  def source(scan: nil, virus: nil, auth_results: nil, authenticated: "no", ip: nil, helo: nil,
             message_id: "<mid-1@remote.test>", subject: "hi")
    headers = [ "Return-Path: <sender@remote.test>",
                "X-Original-To: #{EMAIL}",
                "X-MailOnRails-Authenticated: #{authenticated}" ]
    headers << "X-MailOnRails-Client-Ip: #{ip}" if ip
    headers << "X-MailOnRails-Helo: #{helo}" if helo
    headers << "X-MailOnRails-Auth-Results: #{auth_results}" if auth_results
    headers << "X-MailOnRails-Scan: #{scan}" if scan
    headers << "X-MailOnRails-Virus: #{virus}" if virus
    headers += [ "Message-ID: #{message_id}",
                 "From: sender@remote.test",
                 "To: #{EMAIL}",
                 "Subject: #{subject}" ]
    headers.join("\r\n") + "\r\n\r\nbody\r\n"
  end

  def infected(signature)
    MailOnRails::ClamavScanner::Result.new(:infected, signature)
  end

  def scanning(result, &block)
    with_scanner(enabled: true, scan: result, &block)
  end

  def pass_verdict
    MailOnRails::RspamdAnalyzer::Result.new(
      status: :ok, action: "no action", score: 0.1, required_score: 6.0,
      spf: "pass", dkim: "pass", dmarc: "pass", auth_results: "mail.test; spf=pass; dkim=pass; dmarc=pass"
    )
  end

  def refuse_rspamd(&block)
    with_rspamd(enabled: true, analyze: ->(*) { raise "rspamd must not run on this path" }, &block)
  end

  def quarantine
    @account.find_mailbox(Mailbox::QUARANTINE)
  end

  test "a locally clean scan delivers to INBOX" do
    scanning(CLEAN) { receive_inbound_email_from_source(source) }

    message = @account.inbox.email_messages.sole
    assert_equal "clean", message.scan_status
    assert_nil quarantine, "no quarantine mailbox should be created for clean mail"
  end

  test "a local infected scan quarantines with its virus name, INBOX untouched" do
    scanning(infected("Local-Sig")) { receive_inbound_email_from_source(source) }

    assert_empty @account.inbox.email_messages
    message = quarantine.email_messages.sole
    assert_equal "infected", message.scan_status
    assert_equal "Local-Sig", message.virus_name
  end

  # Security: a sender who smuggles X-MailOnRails-Scan/-Virus past a broken edge
  # must not be able to skip scanning. The forged "clean" is ignored and the
  # real scan (infected) still quarantines.
  test "a forged X-MailOnRails-Scan header is ignored and the message is still scanned" do
    scanning(infected("Real-Sig")) do
      receive_inbound_email_from_source(source(scan: "clean", virus: nil))
    end

    assert_empty @account.inbox.email_messages
    message = quarantine.email_messages.sole
    assert_equal "infected", message.scan_status
    assert_equal "Real-Sig", message.virus_name
  end

  # With scanning off, a forged scan header must not fabricate a scan_status.
  test "a forged X-MailOnRails-Scan header sets no status when scanning is off" do
    receive_inbound_email_from_source(source(scan: "infected", virus: "Fake"))

    message = @account.inbox.email_messages.sole
    assert_nil message.scan_status
    assert_nil message.virus_name
    assert_nil quarantine
  end

  test "retry-duplicated unscanned copies dedup by Message-ID" do
    scanning(UNAVAILABLE) do
      2.times { |i| receive_inbound_email_from_source(source(subject: "attempt #{i}")) }
    end

    assert_equal 1, quarantine.email_messages.count
    assert_equal "unscanned", quarantine.email_messages.sole.scan_status
  end

  # The unscanned copy and the later clean retry share a Message-ID but differ
  # in bytes (subject), so Action Mailbox's ingress dedup lets both through and
  # the mailroom-level sweep is what removes the stale unscanned row.
  test "a clean delivery sweeps stale unscanned copies but never infected ones" do
    scanning(UNAVAILABLE) { receive_inbound_email_from_source(source(subject: "try 1")) }
    scanning(infected("Sig")) { receive_inbound_email_from_source(source(message_id: "<other@remote.test>")) }
    assert_equal 2, quarantine.email_messages.count

    scanning(CLEAN) { receive_inbound_email_from_source(source(subject: "try 2")) }

    assert_equal 1, @account.inbox.email_messages.count
    remaining = quarantine.email_messages.sole
    assert_equal "infected", remaining.scan_status, "the sweep must only remove unscanned rows"
  end

  test "a local scanner outage quarantines the message as unscanned" do
    scanning(UNAVAILABLE) { receive_inbound_email_from_source(source) }

    assert_empty @account.inbox.email_messages
    assert_equal "unscanned", quarantine.email_messages.sole.scan_status
  end

  test "no scanner configured means plain INBOX delivery" do
    receive_inbound_email_from_source(source)

    message = @account.inbox.email_messages.sole
    assert_nil message.scan_status
    assert_nil quarantine
  end

  test "rspamd computes and stamps sender-auth for unauthenticated inbound" do
    facts = {}
    analyze = lambda do |_raw, **kw|
      facts.replace(kw)
      pass_verdict
    end

    with_rspamd(enabled: true, analyze: analyze) do
      receive_inbound_email_from_source(source(ip: "203.0.113.9", helo: "mx.remote.test"))
    end

    message = @account.inbox.email_messages.sole
    assert_equal "mail.test; spf=pass; dkim=pass; dmarc=pass", message.auth_results
    assert message.sender_verified?, "dmarc=pass should verify the sender"
    # The rspamd spam verdict is persisted for the analysis footer.
    assert_equal 0.1, message.spam_score
    assert_equal 6.0, message.spam_threshold
    assert_equal "no action", message.spam_action
    # The exim-stamped connection facts must reach rspamd.
    assert_equal "203.0.113.9", facts[:ip]
    assert_equal "mx.remote.test", facts[:helo]
    assert_equal "sender@remote.test", facts[:mail_from]
  end

  test "an authenticated submission skips rspamd and stays unverified-by-auth" do
    refuse_rspamd do
      receive_inbound_email_from_source(source(authenticated: "user@example.test"))
    end

    message = @account.inbox.email_messages.sole
    assert_nil message.auth_results
    assert_nil message.spam_score, "authenticated submitters are not rspamd-scored"
    assert_equal "user@example.test", message.authenticated_as
  end

  # Security: a forged Auth-Results header must not stand in for a real verdict.
  test "a forged X-MailOnRails-Auth-Results header is ignored when rspamd is off" do
    receive_inbound_email_from_source(source(auth_results: "spoofed; dmarc=pass"))

    message = @account.inbox.email_messages.sole
    assert_nil message.auth_results
    assert_not message.sender_verified?, "a forged Auth-Results header must not verify the sender"
  end

  test "rspamd is authoritative over any inbound Auth-Results header" do
    with_rspamd(enabled: true, analyze: pass_verdict) do
      receive_inbound_email_from_source(source(auth_results: "spoofed; dmarc=fail", ip: "203.0.113.9"))
    end

    assert_equal "mail.test; spf=pass; dkim=pass; dmarc=pass", @account.inbox.email_messages.sole.auth_results
  end

  test "rspamd unavailable still delivers to INBOX without verdicts" do
    with_rspamd(enabled: true, analyze: MailOnRails::RspamdAnalyzer::Result.new(status: :unavailable)) do
      receive_inbound_email_from_source(source(ip: "203.0.113.9", helo: "mx.remote.test"))
    end

    message = @account.inbox.email_messages.sole
    assert_nil message.auth_results
    assert_not message.sender_verified?
  end
end
