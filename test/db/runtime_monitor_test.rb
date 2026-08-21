# frozen_string_literal: true

require_relative "test_helper"

# The Runtime monitor: dead or unhealthy servers are drained and
# restarted with escalating backoff; stop_servers stops the monitor
# first so no restart can race a shutdown. start_protocol is stubbed -
# the server internals have their own suites.
class RuntimeMonitorTest < Minitest::Test
  FakeServer = Struct.new(:healthy) do
    def healthy? = healthy
    def refresh_denylist = nil
  end

  FakeHandle = Struct.new(:server, :thread, keyword_init: true) do
    def ready? = true
    def wait_ready(_timeout = 15) = true
    def shutdown(drain: 5) = nil
  end

  def setup
    # The suite's Rails stub has no env; the runtime consults it.
    Rails.singleton_class.attr_accessor :env unless Rails.respond_to?(:env)
    Rails.env = ActiveSupport::StringInquirer.new("test")
    @runtime = MailOnRails::Runtime
    @original_start = @runtime.method(:start_protocol)
    @runtime.monitor_interval = 0.02
  end

  def teardown
    @runtime.stop_servers
    @runtime.define_singleton_method(:start_protocol, @original_start)
    @runtime.monitor_interval = nil
    @runtime.restart_backoff = nil
  end

  def stub_start(&builder)
    starts = []
    runtime = @runtime
    runtime.define_singleton_method(:start_protocol) do |protocol|
      starts << protocol
      builder.call(protocol)
    end
    starts
  end

  def wait_until(timeout = 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    sleep 0.01 until yield || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
  end

  test "an unhealthy server is restarted" do
    handles = []
    starts = stub_start do
      FakeHandle.new(server: FakeServer.new(true), thread: Thread.new { sleep }).tap { |h| handles << h }
    end
    @runtime.restart_backoff = [ 0, 0 ]
    @runtime.start_servers(protocols: [ :smtp ])
    assert_equal [ :smtp ], starts

    handles.first.server.healthy = false
    wait_until { starts.size >= 2 }
    assert_operator starts.size, :>=, 2, "the monitor must restart an unhealthy server"
    assert @runtime.server(:smtp).healthy?, "the replacement handle must be live"
    assert @runtime.ready?
  end

  test "a dead server thread is restarted" do
    dead = Thread.new { nil }
    dead.join
    threads = [ dead ]
    starts = stub_start do
      FakeHandle.new(server: FakeServer.new(true), thread: threads.shift || Thread.new { sleep })
    end
    @runtime.restart_backoff = [ 0, 0 ]
    @runtime.start_servers(protocols: [ :imap ])
    wait_until { starts.size >= 2 }
    assert_operator starts.size, :>=, 2
    assert_predicate @runtime.server(:imap), :healthy?
  end

  test "restarts back off while the failure persists" do
    starts = stub_start do
      FakeHandle.new(server: FakeServer.new(false), thread: Thread.new { sleep })
    end
    @runtime.restart_backoff = [ 0, 60 ] # attempt 1 immediate, attempt 2 gated far away
    @runtime.start_servers(protocols: [ :smtp ])
    wait_until { starts.size >= 2 }
    sleep 0.15 # several monitor passes
    assert_equal 2, starts.size, "further restarts must wait out the backoff gate"
    refute @runtime.ready?, "an unhealthy protocol must fail readiness"
  end

  test "stop_servers stops the monitor before draining" do
    stub_start { FakeHandle.new(server: FakeServer.new(true), thread: Thread.new { sleep }) }
    @runtime.start_servers(protocols: [ :smtp ])
    monitor = @runtime.instance_variable_get(:@monitor)
    assert_predicate monitor, :alive?

    @runtime.stop_servers
    refute_predicate monitor, :alive?
    assert_nil @runtime.server(:smtp)
    refute @runtime.ready?
  end
end

# The production boot guard for virus scanning: an empty SMTP_CLAMAV_ADDR
# must fail the boot unless the operator explicitly opted out - running
# without a scanner has to be a decision, not a forgotten env. (The guard
# only runs when Rails.env is production; here it is called directly.)
class RuntimeVirusScannerGuardTest < Minitest::Test
  def teardown
    MailOnRails::Settings.reset!
  end

  test "an empty clamd address fails the production boot" do
    MailOnRails::Settings.overrides = { smtp_clamav_addr: "" }
    error = assert_raises(RuntimeError) { MailOnRails::Smtp::Protocol.require_virus_scanner! }
    assert_match(/SMTP_CLAMAV_ADDR/, error.message)
    assert_match(/SMTP_CLAMAV_OPTIONAL/, error.message)
  end

  test "SMTP_CLAMAV_OPTIONAL permits booting without a scanner" do
    MailOnRails::Settings.overrides = { smtp_clamav_addr: "", smtp_clamav_optional: true }
    assert_nil MailOnRails::Smtp::Protocol.require_virus_scanner!
  end

  test "a configured clamd address boots" do
    MailOnRails::Settings.overrides = { smtp_clamav_addr: "127.0.0.1:3310" }
    assert_nil MailOnRails::Smtp::Protocol.require_virus_scanner!
  end
end
