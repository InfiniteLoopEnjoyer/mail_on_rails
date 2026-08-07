require "test_helper"
require "mail_on_rails/store"
require "mail_on_rails/store/with_source"

class WithSourceTest < ActiveSupport::TestCase
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

  setup do
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
end
