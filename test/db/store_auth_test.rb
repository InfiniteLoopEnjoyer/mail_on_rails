# frozen_string_literal: true

require_relative "test_helper"
require "stringio"

# Store::Base's credential checks as the mail edges use them: the
# account-scope exemption for a source that logged in to the account
# lately, the reservation that makes the failure budget hold against
# parallel guesses, and the accounting that must survive whatever goes
# wrong around the verdict.
class StoreAuthTest < DbSuite::TestCase
  OWNER = "owner@example.test"
  PASSWORD = "correct-horse-battery"
  HOME = "198.51.100.7"

  def setup
    super
    @env = %w[MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES
              MAIL_ON_RAILS_HONEYPOT_COLLATERAL_DAYS MAIL_ON_RAILS_AUTH_AUTO_BAN]
    ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"] = "3"
    @min_cost = ActiveModel::SecurePassword.min_cost
    ActiveModel::SecurePassword.min_cost = true
    MailOnRails::EmailAccount.create!(email: OWNER, password: PASSWORD)
    MailOnRails::EmailAccount.create!(email: "other@example.test", password: PASSWORD)
  end

  def teardown
    @env.each { |name| ENV.delete(name) }
    ActiveModel::SecurePassword.min_cost = @min_cost
  end

  def store = @store ||= MailOnRails::Store::WithSource.new(MailOnRails::Store::Base.new, "imap")

  # A finished session, as Server#report_closed hands it to the store.
  def closed_session(ip:, user: nil, protocol: "imap", closed_at: Time.current, messages: nil)
    store.record_closed_connection(protocol: protocol, ip: ip, port: 993, user: user, messages: messages,
                                   connected_at: closed_at - 60, closed_at: closed_at, duration_seconds: 60)
  end

  # Strangers guess at +email+ until its account scope blocks.
  def lock_out(email = OWNER)
    3.times { |i| store.authenticate(email, "guess#{i}", ip: "203.0.113.#{i + 1}") }
    assert_equal "account", MailOnRails::AuthThrottle.check(ip: nil, email: email)&.fetch(:scope), "the account is blocked"
  end

  # Replaces a singleton method for the block.
  def stubbed(receiver, name, body)
    original = receiver.method(name)
    receiver.define_singleton_method(name, &body)
    yield
  ensure
    receiver.define_singleton_method(name, original)
  end

  def captured_log
    io = StringIO.new
    original = MailOnRails.logger
    MailOnRails.logger = ActiveSupport::Logger.new(io)
    yield
    io.string
  ensure
    MailOnRails.logger = original
  end

  def ip_failures(ip) = MailOnRails::AuthThrottle.ip_failures(ip)

  def account_row(email = OWNER) = MailOnRails::AuthThrottle.find_by(scope: "account", key: email)

  # -- M2: the account block is not a lockout tool ------------------------

  test "strangers' wrong guesses do not lock the owner out of a source they logged in from" do
    closed_session(ip: HOME, user: OWNER)
    lock_out

    # SCRAM first: the successful login below clears the account's block.
    assert store.scram_credentials(OWNER, ip: HOME)[:salt_base64], "the owner is served SCRAM material from home"
    result = store.authenticate(OWNER, PASSWORD, ip: HOME)
    assert result[:account_id], "and gets in with the password: #{result.inspect}"
    assert_nil account_row, "which clears the block for everyone, as any successful login does"
  end

  test "an address that never logged in to the account is still refused, right password or not" do
    closed_session(ip: HOME, user: OWNER)
    lock_out

    assert store.authenticate(OWNER, PASSWORD, ip: "192.0.2.50")[:throttled]
    assert store.scram_credentials(OWNER, ip: "192.0.2.50")[:throttled]
    assert store.authenticate(OWNER, PASSWORD)[:throttled], "no address at all is no evidence"
  end

  test "the exemption reaches SMTP logins and SMTP history alike" do
    smtp = MailOnRails::Store::WithSource.new(MailOnRails::Store::Base.new, "smtp")
    closed_session(ip: HOME, user: OWNER, protocol: "smtp")
    lock_out

    assert smtp.scram_credentials(OWNER, ip: HOME)[:salt_base64]
    assert smtp.authenticate(OWNER, PASSWORD, ip: HOME)[:account_id]
  end

  test "a session that is still open counts as much as a closed one" do
    store.sync_ops_state(
      listener: { listener_id: "L1", protocol: "imap", pid: 1, hostname: "h", ports: [ 993 ],
                  max_connections: 100, ready: true, started_at: Time.current },
      connections: [ { connection_id: 1, peer_ip: HOME, port: 993, connected_at: Time.current, user: OWNER } ]
    )
    lock_out

    assert store.authenticate(OWNER, PASSWORD, ip: HOME)[:account_id]
  end

  test "the exemption cannot be earned by failing, by delivering mail, or by logging in elsewhere" do
    attacker = "192.0.2.66"
    closed_session(ip: attacker)                                  # connected, failed or never tried
    closed_session(ip: attacker, messages: 3, protocol: "smtp")   # delivered mail as an MX peer
    closed_session(ip: attacker, user: "other@example.test")      # holds some other account here
    store.authenticate(OWNER, "wrong", ip: attacker)              # a failed attempt at this one
    store.sync_ops_state(
      listener: { listener_id: "L1", protocol: "imap", pid: 1, hostname: "h", ports: [ 993 ],
                  max_connections: 100, ready: true, started_at: Time.current },
      connections: [ { connection_id: 1, peer_ip: attacker, port: 993, connected_at: Time.current,
                       user: "other@example.test" },
                     { connection_id: 2, peer_ip: attacker, port: 993, connected_at: Time.current } ]
    )
    lock_out

    assert store.authenticate(OWNER, PASSWORD, ip: attacker)[:throttled]
    assert store.scram_credentials(OWNER, ip: attacker)[:throttled]
  end

  test "the exemption is per account: the owner's source gets no pass on another blocked account" do
    closed_session(ip: HOME, user: OWNER)
    lock_out("other@example.test")

    assert store.authenticate("other@example.test", PASSWORD, ip: HOME)[:throttled]
  end

  test "a known source's wrong passwords still count against it, and its ip block still holds" do
    ENV["MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES"] = "2"
    closed_session(ip: HOME, user: OWNER)
    lock_out

    2.times { assert_nil store.authenticate(OWNER, "stale-password", ip: HOME)[:account_id] }
    assert_equal 2, ip_failures(HOME)
    result = store.authenticate(OWNER, PASSWORD, ip: HOME)
    assert result[:throttled], "the ip scope applies to a known source like any other"
    assert_equal "ip", MailOnRails::AuthThrottle.check(ip: HOME, email: nil)[:scope]
  end

  test "the exemption lapses with the lookback window" do
    ENV["MAIL_ON_RAILS_HONEYPOT_COLLATERAL_DAYS"] = "7"
    closed_session(ip: HOME, user: OWNER, closed_at: 8.days.ago)
    lock_out
    assert store.authenticate(OWNER, PASSWORD, ip: HOME)[:throttled], "a login 8 days ago is too old"

    closed_session(ip: HOME, user: OWNER, closed_at: 6.days.ago)
    assert store.authenticate(OWNER, PASSWORD, ip: HOME)[:account_id]
  end

  test "an ipv6 source is known by its /64" do
    closed_session(ip: "2001:db8:1:2::10", user: OWNER)
    lock_out

    assert store.authenticate(OWNER, PASSWORD, ip: "2001:db8:1:3::10")[:throttled], "the next /64 is a stranger"
    assert store.authenticate(OWNER, PASSWORD, ip: "2001:db8:1:2:aaaa::99")[:account_id], "same /64"
  end

  test "a failing evidence lookup means no exemption" do
    closed_session(ip: HOME, user: OWNER)
    lock_out

    stubbed(MailOnRails::ClosedConnection, :logged_in_from?, ->(*, **) { raise ActiveRecord::StatementInvalid, "boom" }) do
      assert store.authenticate(OWNER, PASSWORD, ip: HOME)[:throttled]
      assert store.scram_credentials(OWNER, ip: HOME)[:throttled]
    end
  end

  test "the web login's check is unchanged: a mail login is no evidence for it" do
    closed_session(ip: HOME, user: OWNER)
    lock_out

    assert_equal "account", MailOnRails::AuthThrottle.check(ip: HOME, email: OWNER)[:scope]
    assert_nil MailOnRails::AuthThrottle.check(ip: HOME, email: OWNER, exempt_known_source: true)
  end

  # -- L8: the budget holds against parallel guesses -----------------------

  test "parallel wrong guesses from many addresses cannot overshoot the account budget" do
    adjudicated = Queue.new
    slow_miss = lambda do |**|
      adjudicated << true
      sleep 0.3 # every guess is in flight at once, as behind a slow bcrypt
      nil
    end
    verdicts = Queue.new
    stubbed(MailOnRails::EmailAccount, :authenticate_by, slow_miss) do
      8.times.map do |i|
        Thread.new do
          ActiveRecord::Base.connection_pool.with_connection do
            result = store.authenticate(OWNER, "guess#{i}", ip: "203.0.113.#{i + 1}")
            verdicts << (result[:throttled] ? :throttled : result[:error] ? :error : :checked)
          end
        end
      end.each(&:join)
    end

    tally = Array.new(verdicts.size) { verdicts.pop }.tally
    assert_equal 3, adjudicated.size, "only the budget's worth of passwords were looked at: #{tally.inspect}"
    assert_equal({ checked: 3, throttled: 5 }, tally)
    assert_equal 3, account_row.failure_count
  end

  test "one failed login counts once in each scope" do
    store.authenticate(OWNER, "wrong", ip: HOME)

    assert_equal 1, ip_failures(HOME)
    assert_equal 1, account_row.failure_count
    assert_equal 1, MailOnRails::AuthAttempt.where(outcome: "bad_credentials").count
  end

  test "a successful login leaves nothing counted" do
    assert store.authenticate(OWNER, PASSWORD, ip: HOME)[:account_id]

    assert_equal 0, ip_failures(HOME)
    assert_nil account_row
    assert_equal 0, MailOnRails::AuthAttempt.count
  end

  test "a right password on the attempt that would have tripped a block trips nothing" do
    ENV["MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES"] = "3"
    2.times { store.authenticate(OWNER, "wrong", ip: HOME) }

    assert store.authenticate(OWNER, PASSWORD, ip: HOME)[:account_id], "the third attempt is adjudicated"
    assert_nil MailOnRails::AuthThrottle.check(ip: HOME, email: OWNER), "and, being right, blocks neither scope"
    assert_equal 2, ip_failures(HOME), "the earlier failures stay on the address"
  end

  # -- L9: client-chosen login names ---------------------------------------

  test "a login name cannot forge a line in the throttle log" do
    evil = "x@y.z\n[mail_on_rails] IMAP login #{OWNER} (#{HOME})"
    3.times { |i| store.authenticate(evil, "a", ip: "203.0.113.#{i + 1}") }

    log = captured_log { assert store.authenticate(evil, "a", ip: "203.0.113.9")[:throttled] }
    lines = log.lines.grep(/auth throttled/)
    assert_equal 1, lines.size
    assert_equal 1, log.lines.size, "one event, one line: #{log.inspect}"
    assert_includes lines.first, "x@y.z?[mail_on_rails]?IMAP?login?#{OWNER}?(#{HOME})"
  end

  test "an over-long login name is bounded before it becomes a key, a column or a log line" do
    long = "#{'a' * 100_000}@example.test"

    log = captured_log do
      result = store.authenticate(long, "x", ip: HOME)
      assert_nil result[:error], "a verdict, not a store error"
      assert_nil result[:account_id]
      3.times { |i| store.authenticate(long, "x", ip: "203.0.113.#{i + 1}") }
      assert store.authenticate(long, "x", ip: "192.0.2.9")[:throttled]
    end

    key = MailOnRails::AuthThrottle.where(scope: "account").sole.key
    assert_operator key.length, :<=, MailOnRails::AuthThrottle::MAX_KEY_LENGTH
    assert_operator MailOnRails::AuthAttempt.pluck(:username).map(&:length).max, :<=, 320
    assert_operator log.lines.map(&:length).max, :<, 400
    assert_equal 1, ip_failures(HOME), "and it is counted like any wrong guess"
  end

  test "a login name the database cannot store is a counted wrong guess, never a store error" do
    [ "owner@example.test\0", "\xFF\xFEowner@example.test".b, "owner@example.test\r\n" ].each_with_index do |name, i|
      ip = "203.0.113.#{50 + i}"
      result = store.authenticate(name, PASSWORD, ip: ip)

      assert_nil result[:error], name.inspect
      assert_nil result[:account_id], "#{name.inspect} is not the owner's address"
      assert_equal 1, ip_failures(ip), name.inspect
      assert_nil store.record_auth_failure(name, ip: ip)[:error]
      assert_equal 2, ip_failures(ip)
      assert_nil store.scram_credentials(name, ip: "192.0.2.#{i + 1}")[:account_id], "SCRAM gets decoy material"
    end
  end

  test "a cleaned-up spelling never authenticates as the account it resembles" do
    # Padding past the cap would truncate to the real address.
    padded = OWNER + ("\0" * 400)

    assert_nil store.authenticate(padded, PASSWORD, ip: HOME)[:account_id]
    assert_nil store.authenticate(OWNER.ljust(400, "\t"), PASSWORD, ip: HOME)[:account_id]
  end

  # -- L11: the verdict survives its bookkeeping ---------------------------

  test "a password bcrypt cannot take is a wrong password, not a store error" do
    result = store.authenticate(OWNER, "guess\0tail", ip: HOME)

    assert_equal({ account_id: nil, email: nil, honeypot: false }, result)
    assert_equal 1, ip_failures(HOME)
    assert_equal 1, account_row.failure_count
  end

  test "a failing attempt log or auto-ban does not turn a wrong password into a store error" do
    ENV["MAIL_ON_RAILS_AUTH_AUTO_BAN"] = "1"
    boom = ->(*, **) { raise ActiveRecord::ConnectionTimeoutError, "simulated pool timeout" }

    result = stubbed(MailOnRails::AuthAttempt, :record, boom) do
      stubbed(MailOnRails::BannedIp, :auto_ban_after_failure, boom) do
        store.authenticate(OWNER, "wrong", ip: HOME)
      end
    end

    assert_equal({ account_id: nil, email: nil, honeypot: false }, result,
                 "the session must hear 'wrong password' so it counts the attempt")
    assert_equal 1, ip_failures(HOME), "and the durable counter already has it"
    assert_equal 1, account_row.failure_count
  end

  test "a failing counter does not stop a reported SCRAM failure from being logged" do
    boom = ->(**) { raise ActiveRecord::ConnectionTimeoutError, "simulated pool timeout" }

    result = stubbed(MailOnRails::AuthThrottle, :record_failure, boom) do
      store.record_auth_failure(OWNER, ip: HOME)
    end

    assert_equal({}, result)
    assert_equal [ [ OWNER, "bad_credentials" ] ], MailOnRails::AuthAttempt.pluck(:username, :outcome)
  end

  test "a failing clean-up does not turn a right password into a store error" do
    boom = ->(*) { raise ActiveRecord::ConnectionTimeoutError, "simulated pool timeout" }

    result = stubbed(MailOnRails::AuthThrottle, :clear_account, boom) do
      store.authenticate(OWNER, PASSWORD, ip: HOME)
    end

    assert result[:account_id]
    assert_equal 0, ip_failures(HOME)
  end

  # -- SCRAM: the session's opt-in to the same reservation -----------------

  test "a reserved SCRAM exchange is counted up front, once, and given back on success" do
    creds = store.scram_credentials(OWNER, ip: HOME, reserve: true)
    assert creds[:salt_base64]
    assert_equal 1, ip_failures(HOME), "counted before the proof arrives"

    store.record_auth_failure(OWNER, ip: HOME, reservation: creds[:reservation])
    assert_equal 1, ip_failures(HOME), "the reported failure is the one already counted"
    assert_equal 1, account_row.failure_count
    assert_equal 1, MailOnRails::AuthAttempt.where(outcome: "bad_credentials").count

    creds = store.scram_credentials(OWNER, ip: HOME, reserve: true)
    assert_equal 2, ip_failures(HOME)
    store.record_auth_success(OWNER, reservation: creds[:reservation])
    assert_equal 1, ip_failures(HOME), "a verified proof gives its count back"
    assert_nil account_row, "and clears the account"
  end

  test "reserved SCRAM exchanges cannot overshoot the budget, and an unreserved one is unchanged" do
    3.times { |i| assert store.scram_credentials(OWNER, ip: "203.0.113.#{i + 1}", reserve: true)[:reservation] }
    assert store.scram_credentials(OWNER, ip: "203.0.113.9", reserve: true)[:throttled]

    plain = store.scram_credentials("other@example.test", ip: HOME)
    assert plain[:salt_base64]
    assert_not plain.key?(:reservation)
    assert_equal 0, ip_failures(HOME)
  end
end
