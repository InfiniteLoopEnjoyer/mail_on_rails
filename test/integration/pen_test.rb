# frozen_string_literal: true

# Sender verification does live DNS; keep MX delivery deterministic.
ENV["SMTP_SENDER_AUTH"] ||= "0"

require "test_helper"
require "net/smtp"
require "net/imap"
require "socket"
require "mail_on_rails/boot"

# Full-stack penetration scenarios: real listeners, real stores, loopback
# clients. Complements the vendored wire suites (which use in-memory stores)
# by exercising the same protections through Boot.start_servers.
class PenTest < ActiveSupport::TestCase
  self.use_transactional_tests = false

  ALICE = "pen-alice@example.test"
  BOB = "pen-bob@example.test"
  PASSWORD = "pw-pen-test-123456"
  REMOTE = "victim@foreign.test"
  BOB_PRIVATE = "Pen-Bob-Private"

  setup do
    @env_keys = %w[MAIL_ON_RAILS_HOST MAIL_ON_RAILS_IMAP_PORT MAIL_ON_RAILS_IMAPS_PORT
                   SMTP_PORT SMTP_SUBMISSION_PORT SMTPS_PORT SMTP_HELO_HOST SMTP_SENDER_AUTH]
    @saved_env = @env_keys.to_h { |k| [ k, ENV[k] ] }

    ENV["MAIL_ON_RAILS_HOST"] = "127.0.0.1"
    ENV["SMTP_SENDER_AUTH"] = "0"
    @imap_port, @imaps_port, @smtp_port, @submission_port, @smtps_port = free_ports(5)
    ENV["MAIL_ON_RAILS_IMAP_PORT"] = @imap_port.to_s
    ENV["MAIL_ON_RAILS_IMAPS_PORT"] = @imaps_port.to_s
    ENV["SMTP_PORT"] = @smtp_port.to_s
    ENV["SMTP_SUBMISSION_PORT"] = @submission_port.to_s
    ENV["SMTPS_PORT"] = @smtps_port.to_s
    ENV["SMTP_HELO_HOST"] = "pen.test"

    @alice = EmailAccount.create!(email: ALICE, password: PASSWORD)
    @bob = EmailAccount.create!(email: BOB, password: PASSWORD)
    @bob.mailboxes.create!(name: BOB_PRIVATE)

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
    ClosedConnection.delete_all
    EmailAccount.where(email: [ ALICE, BOB ]).destroy_all
  end

  test "mx open relay is refused and failed auth is audited on the live listener" do
    reply = smtp_dialog(port: @smtp_port, lines: [
      "EHLO pen-client.test",
      "MAIL FROM:<attacker@evil.test>",
      "RCPT TO:<#{REMOTE}>",
      "QUIT"
    ])
    assert_match(/550 5\.7\.1 Relaying denied/, reply)
    assert_equal 0, ActionMailbox::InboundEmail.count
    assert_equal 0, SmtpOutboundMessage.count

    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    bad = Net::SMTP.new("127.0.0.1", @smtps_port)
    bad.enable_tls(ctx)
    assert_raises(Net::SMTPAuthenticationError) do
      bad.start("pen-client.test", ALICE, "wrong-password", :plain)
    end
    attempt = AuthAttempt.order(:id).last
    assert attempt, "failed SMTP AUTH must land in auth_attempts"
    assert_equal "smtp", attempt.source
    assert_equal ALICE, attempt.username
  end

  test "submission rejects envelope spoof after authentication" do
    token = [ "\0#{ALICE}\0#{PASSWORD}" ].pack("m0")
    reply = smtp_dialog(port: @submission_port, lines: [
      "EHLO pen-client.test",
      "STARTTLS",
      "EHLO pen-client.test",
      "AUTH PLAIN #{token}",
      "MAIL FROM:<#{BOB}>",
      "QUIT"
    ])
    assert_match(/550 Sender address must match authenticated account/, reply)
    assert_equal 0, SmtpOutboundMessage.count
  end

  test "imap list does not reveal another accounts private mailbox on the live listener" do
    imap = Net::IMAP.new("127.0.0.1", port: @imaps_port, ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE })
    begin
      imap.login(ALICE, PASSWORD)
      names = imap.list("", "*").map(&:name)
      assert_includes names, "INBOX"
      refute_includes names, BOB_PRIVATE
    ensure
      imap.logout rescue nil
      imap.disconnect rescue nil
    end
  end

  private

  # All sockets stay bound until every port is issued: bind-then-close one
  # at a time lets the kernel hand the same port out twice, and the daemon
  # refuses duplicate listener ports.
  def free_ports(count)
    servers = Array.new(count) { TCPServer.new("127.0.0.1", 0) }
    servers.map { |s| s.addr[1] }
  ensure
    servers&.each(&:close)
  end

  # Minimal SMTP client: optional STARTTLS or implicit TLS, returns concatenated replies.
  def smtp_dialog(port:, lines:, tls: :none)
    socket = TCPSocket.new("127.0.0.1", port)
    socket.timeout = 5
    io = if tls == :implicit
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      tls_socket = OpenSSL::SSL::SSLSocket.new(socket, ctx)
      tls_socket.sync_close = true
      tls_socket.connect
      tls_socket
    else
      socket
    end
    replies = +io.gets("\r\n").to_s
    lines.each do |line|
      if line == "STARTTLS"
        io.write("STARTTLS\r\n")
        replies << read_smtp_reply(io)
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        io = OpenSSL::SSL::SSLSocket.new(socket, ctx)
        io.sync_close = true
        io.connect
        next
      end
      io.write("#{line}\r\n")
      replies << read_smtp_reply(io)
    end
    replies
  ensure
    io.close rescue nil
  end

  def read_smtp_reply(io)
    buffer = +""
    loop do
      chunk = io.gets("\r\n")
      break unless chunk
      buffer << chunk
      break if chunk[3] == " "
    end
    buffer
  end
end
