# Sender verification does live DNS; the constant is read at require time
# (nothing else in the app suite loads the SMTP server files).
ENV["SMTP_SENDER_AUTH"] ||= "0"

require "test_helper"
require "net/smtp"
require "net/imap"
require "socket"
require "mail_on_rails/boot"

# The whole unified stack end-to-end, in one process like production:
# Boot.start_servers on ephemeral ports with the real ActiveRecord
# stores, then real Net::SMTP / Net::IMAP clients over loopback sockets.
#
# Transactional tests are off: the servers' connection threads use their
# own database connections and must see the test's rows, so everything
# committed here is cleaned up by hand in teardown.
class InProcessServersTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  self.use_transactional_tests = false

  EMAIL = "endtoend@example.test"
  PASSWORD = "pw-123456-endtoend"

  setup do
    @env_keys = %w[MAIL_ON_RAILS_HOST MAIL_ON_RAILS_IMAP_PORT MAIL_ON_RAILS_IMAPS_PORT
                   SMTP_PORT SMTP_SUBMISSION_PORT SMTPS_PORT SMTP_HELO_HOST]
    @saved_env = @env_keys.to_h { |k| [ k, ENV[k] ] }

    ENV["MAIL_ON_RAILS_HOST"] = "127.0.0.1"
    @imap_port, @imaps_port, @smtp_port, @submission_port, @smtps_port = 5.times.map { free_port }
    ENV["MAIL_ON_RAILS_IMAP_PORT"] = @imap_port.to_s
    ENV["MAIL_ON_RAILS_IMAPS_PORT"] = @imaps_port.to_s
    ENV["SMTP_PORT"] = @smtp_port.to_s
    ENV["SMTP_SUBMISSION_PORT"] = @submission_port.to_s
    ENV["SMTPS_PORT"] = @smtps_port.to_s
    ENV["SMTP_HELO_HOST"] = "unified.test"

    @account = EmailAccount.create!(email: EMAIL, password: PASSWORD)

    MailOnRails::Boot.start_servers
    MailOnRails::Boot.wait_ready!(10)
  end

  teardown do
    MailOnRails::Boot.stop_servers(drain: 1)
    @saved_env.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }

    ActionMailbox::InboundEmail.destroy_all
    SmtpOutboundMessage.delete_all
    AuthAttempt.delete_all
    AuthThrottle.delete_all
    EmailAccount.where(email: EMAIL).destroy_all
  end

  test "the full stack serves SMTP inbound, submission, and IMAP in one process" do
    assert MailOnRails::Boot.ready?

    # -- inbound MX: unauthenticated plaintext delivery for a local user --
    raw = "Message-ID: <e2e-#{SecureRandom.hex(4)}@remote.test>\r\n" \
          "From: sender@remote.test\r\nTo: #{EMAIL}\r\nSubject: unified e2e\r\n\r\nhello from the wire\r\n"
    # tls_verify: false because the listener serves the self-signed dev
    # cert; Net::SMTP still upgrades via STARTTLS.
    Net::SMTP.start("127.0.0.1", @smtp_port, helo: "client.test", tls_verify: false) do |smtp|
      smtp.send_message(raw, "sender@remote.test", EMAIL)
    end

    assert_equal 1, ActionMailbox::InboundEmail.count
    source = ActionMailbox::InboundEmail.last.raw_email.download
    assert_includes source, "X-MailOnRails-Client-Ip: 127.0.0.1\r\n"
    assert_includes source, "X-Original-To: #{EMAIL}\r\n"
    # ESMTPS: Net::SMTP upgraded via STARTTLS before sending.
    assert_match(/^Received: from client\.test \(\[127\.0\.0\.1\]\)\r\n\tby unified\.test with ESMTPS;/, source)

    # Route it through the mailroom (Action Mailbox enqueues routing).
    perform_enqueued_jobs

    inbox_message = @account.reload.inbox.email_messages.last
    assert inbox_message, "the mailroom must file the message into INBOX"
    assert_equal "unified e2e", inbox_message.subject

    # -- IMAP over implicit TLS: login and read the message back --
    imap = Net::IMAP.new("127.0.0.1", port: @imaps_port, ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE })
    begin
      imap.login(EMAIL, PASSWORD)
      imap.select("INBOX")
      uids = imap.uid_search([ "ALL" ])
      assert_equal 1, uids.size
      fetched = imap.uid_fetch(uids, "BODY[]").first.attr["BODY[]"]
      assert_includes fetched, "hello from the wire"
      assert_includes fetched, "X-MailOnRails-Client-Ip: 127.0.0.1"
    ensure
      imap.logout rescue nil
      imap.disconnect rescue nil
    end

    # -- authenticated submission over SMTPS: queued for outbound delivery --
    outbound = "From: #{EMAIL}\r\nTo: friend@elsewhere.test\r\nSubject: outbound e2e\r\n\r\nbye\r\n"
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    smtp = Net::SMTP.new("127.0.0.1", @smtps_port)
    smtp.enable_tls(ctx)
    smtp.start("client.test", EMAIL, PASSWORD, :plain) do |session|
      session.send_message(outbound, EMAIL, "friend@elsewhere.test")
    end

    row = SmtpOutboundMessage.last
    assert row, "submission must row into the outbound queue"
    assert_equal "friend@elsewhere.test", row.recipient
    assert_equal EMAIL, row.mail_from
    assert_predicate row, :pending?

    # -- a failed AUTH lands in the shared attempt log with source smtp --
    bad = Net::SMTP.new("127.0.0.1", @smtps_port)
    bad.enable_tls(ctx)
    assert_raises(Net::SMTPAuthenticationError) do
      bad.start("client.test", EMAIL, "wrong-password", :plain)
    end
    attempt = AuthAttempt.last
    assert attempt, "failed SMTP AUTH must be recorded"
    assert_equal "smtp", attempt.source
    assert_equal "127.0.0.1", attempt.ip

    # -- unknown local user vs foreign recipient split --
    Net::SMTP.start("127.0.0.1", @smtp_port, helo: "client.test", tls_verify: false) do |session|
      session.mailfrom("sender@remote.test")
      error = assert_raises(Net::SMTPFatalError) { session.rcptto("nobody@example.test") }
      assert_match(/5\.1\.1 No such user/, error.message)
      error = assert_raises(Net::SMTPFatalError) { session.rcptto("nobody@foreign.test") }
      assert_match(/5\.7\.1 Relaying denied/, error.message)
    end
  end

  test "stop_servers drains and unbinds every listener" do
    assert MailOnRails::Boot.ready?

    MailOnRails::Boot.stop_servers(drain: 1)

    refute MailOnRails::Boot.ready?
    [ @imap_port, @imaps_port, @smtp_port, @submission_port, @smtps_port ].each do |port|
      assert_raises(Errno::ECONNREFUSED, "port #{port} must be unbound") { TCPSocket.new("127.0.0.1", port) }
    end
  end

  private

  # Bind-then-close to find a free ephemeral port; the tiny reuse race is
  # acceptable on loopback in a test.
  def free_port
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    server.close
    port
  end
end
