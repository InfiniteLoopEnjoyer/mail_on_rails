require "test_helper"
require "mail_on_rails/store"
require "mail_on_rails/smtp/store/contracts"

# The Active Record implementation behind the in-process SMTP server must
# satisfy the store contract - the same suite runs against
# MailOnRails::Smtp::Store::Memory in the vendored server tests
# (test/vendored/smtp) - plus the app-specific behavior the contract can't
# see: InboundEmail creation with stamped trust headers, outbound rows,
# quarantine filing, and AuthAttempt logging.
class SmtpBackendTest < ActiveSupport::TestCase
  include MailOnRails::Smtp::Store::Contracts::Smtp

  RAW_MESSAGE = "Message-ID: <m1@remote.test>\r\nFrom: sender@remote.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def create_account(email:, password:)
    EmailAccount.create!(email: email, password: password).id
  end

  def build_store(outbound_limit: nil)
    @outbound_limit = outbound_limit
    MailOnRails::Store::SmtpBackend.new
  end

  # The contract's outbound-limit test provisions a store with
  # outbound_limit: 1; the backend reads MAIL_ON_RAILS_OUTBOUND_LIMIT.
  def store
    @store ||= build_store
    if @outbound_limit
      ENV["MAIL_ON_RAILS_OUTBOUND_LIMIT"] = @outbound_limit.to_s
    end
    @store
  end

  teardown do
    ENV.delete("MAIL_ON_RAILS_OUTBOUND_LIMIT")
  end

  EMAIL = MailOnRails::Smtp::Store::Contracts::Helpers::EMAIL
  PASSWORD = MailOnRails::Smtp::Store::Contracts::Helpers::PASSWORD

  test "aliases count as local recipients" do
    account = EmailAccount.find(account_id)
    account.email_aliases.create!(email: "alias@example.test")

    result = store.local_rcpts([ "Alias@Example.test" ])

    assert_equal [ "alias@example.test" ], result[:local]
  end

  test "hosted domains come from the Domain table too" do
    Domain.create!(name: "hosted.test")

    result = store.local_rcpts([ "nobody@hosted.test", "nobody@foreign.test" ])

    assert_equal [ "nobody@hosted.test" ], result[:unknown_in_local_domain]
  end

  test "inbound mail becomes an InboundEmail with stamped trust headers" do
    account_id
    wire = "X-MailOnRails-Authenticated: forged@evil.test\r\nReturn-Path: <forged@evil.test>\r\n" + RAW_MESSAGE

    assert_difference -> { ActionMailbox::InboundEmail.count }, 1 do
      result = store.smtp_store("sender@remote.test", [ EMAIL ], wire, nil,
                                client_ip: "203.0.113.9", helo: "mail.remote.test")
      assert result[:id]
    end

    source = ActionMailbox::InboundEmail.last.raw_email.download
    assert_includes source, "Return-Path: <sender@remote.test>\r\n"
    assert_includes source, "X-Original-To: #{EMAIL}\r\n"
    assert_includes source, "X-MailOnRails-Authenticated: no\r\n"
    assert_includes source, "X-MailOnRails-Client-Ip: 203.0.113.9\r\n"
    assert_includes source, "X-MailOnRails-Helo: mail.remote.test\r\n"
    refute_includes source, "forged@evil.test", "wire copies of trusted headers must be stripped"
  end

  test "authenticated submission to a remote recipient rows into the outbound queue" do
    account_id

    assert_difference -> { SmtpOutboundMessage.count }, 1 do
      result = store.smtp_store(EMAIL, [ "friend@elsewhere.test" ], RAW_MESSAGE, EMAIL,
                                client_ip: "198.51.100.7", helo: "client.test")
      assert_equal 1, result[:outbound]
    end

    row = SmtpOutboundMessage.last
    assert_equal EMAIL, row.mail_from
    assert_equal "friend@elsewhere.test", row.recipient
    assert_predicate row, :pending?
  end

  test "quarantine files into the recipient's Quarantine mailbox and dedupes by message id" do
    account = EmailAccount.find(account_id)

    2.times do
      store.quarantine("sender@remote.test", [ EMAIL ], RAW_MESSAGE, nil,
                       client_ip: "203.0.113.9", helo: "mail.remote.test",
                       auth_results: nil, scan_status: "infected", virus: "Eicar-Test-Signature")
    end

    messages = account.quarantine_mailbox.email_messages
    assert_equal 1, messages.count, "a retried message must not quarantine twice"
    message = messages.first
    assert_equal "infected", message.scan_status
    assert_equal "Eicar-Test-Signature", message.virus_name
    assert_includes message.raw, "X-MailOnRails-Client-Ip: 203.0.113.9\r\n"
  end

  test "quarantine falls back to the authenticated submitter's account" do
    account = EmailAccount.find(account_id)

    store.quarantine(EMAIL, [ "friend@elsewhere.test" ], RAW_MESSAGE, EMAIL,
                     client_ip: nil, helo: nil, auth_results: nil, scan_status: "unscanned")

    assert_equal 1, account.quarantine_mailbox.email_messages.count
  end

  test "failed auth lands in AuthAttempt with source smtp" do
    account_id

    assert_difference -> { AuthAttempt.count }, 1 do
      store.authenticate(EMAIL, "wrong", ip: "198.51.100.7")
    end

    attempt = AuthAttempt.last
    assert_equal "smtp", attempt.source
    assert_equal "198.51.100.7", attempt.ip
    assert_equal EMAIL, attempt.username
  end
end
