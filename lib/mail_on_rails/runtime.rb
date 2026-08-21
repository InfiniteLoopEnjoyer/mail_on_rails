# frozen_string_literal: true

module MailOnRails
  # Lifecycle glue for the mail servers. Protocol gems register an adapter
  # here when they load (see MailOnRails::Smtp::Protocol and
  # MailOnRails::Imap::Protocol); the runtime starts each requested
  # protocol through its adapter on a background thread and keeps the
  # handles for readiness checks (host apps gate /up on MailOnRails.ready?)
  # and graceful shutdown (the Puma plugin's stop hooks, or the standalone
  # CLI's signal handler).
  #
  # A monitor thread supervises the running servers: a server whose thread
  # has died, or that reports itself unhealthy (a listener's accept loop
  # crashed - see Netserv::Server#healthy?), is drained and restarted with
  # escalating backoff, so a transient failure (momentary port conflict,
  # store hiccup at bind time) heals without a deploy. While a protocol is
  # down `ready?` is false, so /up fails - deliberate: a mail port that
  # cannot come back should page, not hide.
  #
  # Which protocols run *in this process* is a separate question from which
  # are installed - see in_process_protocols.
  module Runtime
    module_function

    MONITOR_INTERVAL = 5
    # Delay before restart attempt N (the last entry repeats). The counter
    # resets after RESTART_FORGIVENESS seconds without a failure.
    RESTART_BACKOFF = [ 0, 5, 10, 30, 60, 300 ].freeze
    RESTART_FORGIVENESS = 600

    # Values of MAIL_ON_RAILS_SERVERS that mean "every installed protocol"
    # and "none" (anything else is a comma-separated subset).
    ENV_ALL = %w[true all 1 yes].freeze
    ENV_NONE = %w[0 false none no off].freeze

    # Test seam: shortens the monitor's cadence.
    def monitor_interval = @monitor_interval || MONITOR_INTERVAL

    def monitor_interval=(seconds)
      @monitor_interval = seconds
    end

    def restart_backoff = @restart_backoff || RESTART_BACKOFF

    def restart_backoff=(delays)
      @restart_backoff = delays
    end

    # -- protocol registry -------------------------------------------------

    # Protocol gems call this at load time. +adapter+ responds to
    # `start(logger:, tls_dir:)` (returns a Handle: ready?, wait_ready,
    # shutdown, server, thread), `check_config(logger:)` (boolean) and
    # `preflight!` (raises on a production misconfiguration).
    def register(protocol, adapter)
      registry[protocol.to_sym] = adapter
    end

    def registry
      @registry ||= {}
    end

    # Installed protocols, in registration order.
    def registered_protocols
      registry.keys
    end

    def registered?(protocol)
      registry.key?(protocol.to_sym)
    end

    def adapter(protocol)
      registry.fetch(protocol.to_sym) do
        raise ArgumentError, "protocol #{protocol.inspect} is not registered - add the " \
                             "mail_on_rails_#{protocol} gem to the Gemfile (installed: " \
                             "#{registered_protocols.join(", ").then { |s| s.empty? ? "none" : s }})"
      end
    end

    # -- which protocols run in this process -------------------------------

    # The protocols the Puma plugin (and a host's /up gate) should treat as
    # living in this process, resolved in order:
    #
    #   1. `config.mail_on_rails.protocols` / MailOnRails.protocols, if the
    #      host set it explicitly (an empty list is a valid answer: UI only);
    #   2. MAIL_ON_RAILS_SERVERS - "true"/"all" (every installed protocol),
    #      "0"/"false"/"none" (nothing), or a subset like "smtp" or
    #      "smtp,imap";
    #   3. otherwise: every installed protocol in development, nothing in
    #      any other environment (production must opt in, exactly as the
    #      previous MAIL_ON_RAILS_SERVERS=true contract required).
    #
    # The CLI (bin/mail_server) does NOT use this: running the mail binary
    # means "serve mail", so it defaults to every installed protocol.
    def in_process_protocols
      explicit = MailOnRails.protocols
      return normalize_protocols(explicit) unless explicit.nil?

      env = ENV["MAIL_ON_RAILS_SERVERS"]
      return parse_protocols(env) unless env.nil?

      environment == "development" ? registered_protocols : []
    end

    # Parses a MAIL_ON_RAILS_SERVERS-style value. Unknown names raise so a
    # typo ("stmp") fails the boot instead of silently serving nothing.
    def parse_protocols(value)
      text = value.to_s.strip.downcase
      return [] if text.empty? || ENV_NONE.include?(text)
      return registered_protocols if ENV_ALL.include?(text)

      normalize_protocols(text.split(/[\s,]+/))
    end

    def normalize_protocols(list)
      Array(list).map { |p| p.to_s.strip.downcase }.reject(&:empty?).uniq.map(&:to_sym).each do |protocol|
        adapter(protocol) # raises for unknown / uninstalled
      end
    end

    # "production", "development", ... - Rails.env when Rails is loaded,
    # else RAILS_ENV / RACK_ENV (the Rails-free CLI path).
    def environment
      return ::Rails.env.to_s if defined?(::Rails) && ::Rails.respond_to?(:env) && ::Rails.env

      ENV["RAILS_ENV"] || ENV["RACK_ENV"] || "development"
    end

    def production?
      environment == "production"
    end

    # -- lifecycle ---------------------------------------------------------

    # Starts one server per requested protocol (default: every installed
    # protocol), plus the monitor, and returns the handles. In production
    # each protocol's adapter runs its preflight first (explicit TLS, a
    # virus scanner for SMTP, ...) so a misconfigured deploy fails to boot
    # instead of quietly serving degraded.
    def start_servers(protocols: nil)
      protocols = normalize_protocols(protocols || registered_protocols)
      protocols.each { |protocol| adapter(protocol).preflight! } if production?
      @handles = {}
      protocols.each { |protocol| @handles[protocol] = start_protocol(protocol) }
      start_monitor
      @handles
    end

    # Boots a single protocol through its adapter. The monitor calls this
    # again when that protocol needs a restart.
    def start_protocol(protocol)
      adapter(protocol).start(logger: MailOnRails.logger, tls_dir: MailOnRails.tls_dir)
    end

    # True once every started server has all its listeners bound and none
    # of them has died. False before start_servers and after stop_servers -
    # a health check must not pass while the mail ports are down.
    def ready?
      handles = (@handles || {}).values
      handles.any? && handles.all? { |handle| handle.ready? && handle.server.healthy? }
    end

    # Protocols this process has started (and not stopped).
    def running_protocols
      (@handles || {}).keys
    end

    # Blocks until every server is ready; raises on timeout so a listener
    # that failed to bind fails the boot (and with it a deploy's health
    # check) instead of leaving a web-only process that looks healthy.
    def wait_ready!(timeout = 15)
      (@handles || {}).each_value do |handle|
        next if handle.wait_ready(timeout)

        raise "mail server listeners failed to bind within #{timeout}s"
      end
    end

    # Graceful shutdown for Puma's stop/restart hooks and the CLI; see
    # Netserv::Server#shutdown for the drain semantics. The monitor is
    # stopped and joined first so no restart can race the drain.
    def stop_servers(drain: MailOnRails.shutdown_drain)
      stop_monitor
      handles = (@handles || {}).values
      @handles = nil
      handles.each { |handle| handle.shutdown(drain: drain) }
    end

    # The running server for :imap or :smtp; nil when that server isn't
    # running in this process. Gem-internal and a test seam - host apps
    # read the ops tables (OpenConnection, Listener, ...) instead, which
    # work whether the listeners are in this process or another container.
    def server(protocol)
      (@handles || {})[protocol]&.server
    end

    # Drops live connections whose peer IP the caller's test matches, on
    # every server running in this process (see Netserv::Server#kick).
    # Returns how many connections were closed. Cross-process callers
    # insert ConnectionKick rows instead.
    def kick_connections(&matcher)
      (@handles || {}).values.sum { |handle| handle.server.kick(&matcher) }
    end

    # Reloads every running server's denylist from the store right now,
    # bypassing its poll interval (see Netserv::Server#refresh_denylist).
    # Called after a BannedIp commit so a new ban applies to the very next
    # connection; a no-server process (tests, a web-only boot) no-ops and
    # the servers' own TTL polling covers cross-process writers.
    def refresh_denylists
      (@handles || {}).each_value { |handle| handle.server.refresh_denylist }
    end

    # -- monitor -----------------------------------------------------------

    def start_monitor
      stop_monitor
      @monitor_mutex = Mutex.new
      @monitor_cv = ConditionVariable.new
      @monitor_stop = false
      @restart_state = {} # protocol => { failures:, next_attempt_at:, last_failure_at: }
      @monitor = Thread.new do
        Thread.current.name = "mail_on_rails_monitor"
        loop do
          @monitor_mutex.synchronize do
            @monitor_cv.wait(@monitor_mutex, monitor_interval) unless @monitor_stop
          end
          break if @monitor_stop

          check_servers
        end
      end
    end

    def stop_monitor
      monitor = @monitor
      return unless monitor

      @monitor = nil
      @monitor_stop = true
      @monitor_mutex&.synchronize { @monitor_cv&.broadcast }
      monitor.join(monitor_interval + 5) unless monitor == Thread.current
    end

    # One monitor pass: restart any server whose thread has died or that
    # reports itself unhealthy, respecting the per-protocol backoff.
    def check_servers
      (@handles || {}).each do |protocol, handle|
        next if handle.thread.alive? && handle.server.healthy?
        break if @monitor_stop

        restart_protocol(protocol, handle)
      end
    rescue StandardError => e
      # The monitor must never die of a transient error - it is the thing
      # that heals transient errors.
      MailOnRails.logger.error("[mail_on_rails] monitor pass failed: #{e.class}: #{e.message}")
    end

    def restart_protocol(protocol, handle)
      state = (@restart_state[protocol] ||= { failures: 0, next_attempt_at: nil, last_failure_at: nil })
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      state[:failures] = 0 if state[:last_failure_at] && now - state[:last_failure_at] > RESTART_FORGIVENESS
      return if state[:next_attempt_at] && now < state[:next_attempt_at]

      state[:failures] += 1
      state[:last_failure_at] = now
      # The gate before the NEXT attempt escalates with the failure count:
      # first restart is immediate, then backoff[1], backoff[2], ...
      backoff = restart_backoff
      delay = backoff[[ state[:failures], backoff.size - 1 ].min]
      state[:next_attempt_at] = now + delay
      MailOnRails.logger.warn("[mail_on_rails] #{protocol} server is down; restarting " \
                              "(attempt #{state[:failures]}, next retry in #{delay}s if it still fails)")

      begin
        handle.shutdown(drain: 0) # reap surviving listeners of a half-dead server
      rescue StandardError
        nil
      end
      begin
        @handles[protocol] = start_protocol(protocol)
      rescue StandardError => e
        MailOnRails.logger.error("[mail_on_rails] #{protocol} restart failed: #{e.class}: #{e.message}")
      end
    end
  end
end
