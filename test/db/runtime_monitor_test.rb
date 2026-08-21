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

  # The protocol gems register the real adapters; the core suite stands
  # in its own (start_protocol is stubbed below anyway).
  module FakeProtocol
    module_function

    def start(logger:, tls_dir:) = raise("stubbed")
    def check_config(logger:) = true
    def preflight! = nil
  end

  def setup
    # The suite's Rails stub has no env; the runtime consults it.
    Rails.singleton_class.attr_accessor :env unless Rails.respond_to?(:env)
    Rails.env = ActiveSupport::StringInquirer.new("test")
    @runtime = MailOnRails::Runtime
    @registered = %i[smtp imap].reject { |p| @runtime.registered?(p) }
    @registered.each { |p| @runtime.register(p, FakeProtocol) }
    @original_start = @runtime.method(:start_protocol)
    @runtime.monitor_interval = 0.02
  end

  def teardown
    @runtime.stop_servers
    @runtime.define_singleton_method(:start_protocol, @original_start)
    @registered.each { |p| @runtime.registry.delete(p) }
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
