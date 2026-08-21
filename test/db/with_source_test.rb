# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/store/with_source"

# Store::WithSource stamps the auth calls with their surface and delegates
# everything else untouched.
class WithSourceTest < Minitest::Test
  class Recorder
    attr_reader :calls

    def initialize = @calls = []

    def authenticate(email, password, ip: nil, source: nil)
      @calls << [ :authenticate, email, password, ip, source ]
      { account_id: 1, email: email }
    end

    def record_auth_failure(email, ip: nil, source: nil)
      @calls << [ :record_auth_failure, email, ip, source ]
      {}
    end

    def log(level, message) = @calls << [ :log, level, message ]

    def select_mailbox(account_id, name) = @calls << [ :select_mailbox, account_id, name ]

    def record_closed_connection(info) = @calls << [ :record_closed_connection, info ]
  end

  def setup
    @backend = Recorder.new
    @store = MailOnRails::Store::WithSource.new(@backend, "imap")
  end

  test "authenticate gains the default source when the session omits it" do
    @store.authenticate("a@b.test", "pw", ip: "10.0.0.1")

    assert_equal [ :authenticate, "a@b.test", "pw", "10.0.0.1", "imap" ], @backend.calls.last
  end

  test "an explicit source wins over the default" do
    @store.record_auth_failure("a@b.test", ip: "10.0.0.1", source: "web")

    assert_equal [ :record_auth_failure, "a@b.test", "10.0.0.1", "web" ], @backend.calls.last
  end

  test "record_auth_failure gains the default source" do
    @store.record_auth_failure("a@b.test", ip: "10.0.0.1")

    assert_equal [ :record_auth_failure, "a@b.test", "10.0.0.1", "imap" ], @backend.calls.last
  end

  test "other contract methods delegate untouched" do
    @store.log(:info, "hello")
    @store.select_mailbox(7, "INBOX")

    assert_includes @backend.calls, [ :log, :info, "hello" ]
    assert_includes @backend.calls, [ :select_mailbox, 7, "INBOX" ]
  end

  # The IMAP server calls this behind respond_to?, so a missing delegation
  # would not raise - IMAP connection history would just silently stop.
  # The vendored tests all use the memory store directly and can never
  # catch that, hence this pin.
  test "record_closed_connection is delegated" do
    assert_respond_to @store, :record_closed_connection

    @store.record_closed_connection({ protocol: "imap" })

    assert_equal [ :record_closed_connection, { protocol: "imap" } ], @backend.calls.last
  end

  # The optional methods are discovered with respond_to?: the wrapper must
  # answer exactly as the backend does - true for a backend that has them
  # (the ops-state projection), false for one that doesn't (a memory
  # store), and never raise on its own account.
  test "respond_to? mirrors the backend for optional store methods" do
    refute_respond_to @store, :sync_ops_state, "the recorder has no ops methods"
    refute_respond_to @store, :pending_kicks

    full = Class.new(Recorder) do
      def sync_ops_state(listener:, connections: nil, lockouts: nil) = @calls << [ :sync_ops_state, listener, connections, lockouts ]
      def pending_kicks(protocol) = @calls << [ :pending_kicks, protocol ]
    end.new
    wrapped = MailOnRails::Store::WithSource.new(full, "imap")
    assert_respond_to wrapped, :sync_ops_state
    assert_respond_to wrapped, :pending_kicks
    wrapped.sync_ops_state(listener: { listener_id: "x" })
    assert_equal [ :sync_ops_state, { listener_id: "x" }, nil, nil ], full.calls.last
    assert_raises(NoMethodError) { wrapped.no_such_method }
  end

  test "the Active Record backend's ops methods pass through the wrapper" do
    wrapped = MailOnRails::Store::WithSource.new(MailOnRails::Store::Base.new, "imap")
    %i[sync_ops_state pending_kicks ack_kick prune_stale_listeners remove_listener
       record_closed_connection record_honeypot_event banned_cidrs].each do |name|
      assert_respond_to wrapped, name
    end
  end
end
