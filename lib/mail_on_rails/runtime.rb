# frozen_string_literal: true

module MailOnRails
  # Lifecycle glue for the in-process mail servers. Builds each protocol's
  # ActiveRecord-backed store and starts the server on a background thread
  # via its Daemon module, keeping the handles for readiness checks (host
  # apps gate /up on MailOnRails.ready?) and graceful shutdown (the Puma
  # plugin's stop hooks, or the standalone CLI's signal handler).
  #
  # A monitor thread supervises the running servers: a server whose thread
  # has died, or that reports itself unhealthy (a listener's accept loop
  # crashed - see Netserv::Server#healthy?), is drained and restarted with
  # escalating backoff, so a transient failure (momentary port conflict,
  # store hiccup at bind time) heals without a deploy. While a protocol is
  # down `ready?` is false, so /up fails - deliberate: a mail port that
  # cannot come back should page, not hide.
  module Runtime
    module_function

    MONITOR_INTERVAL = 5
    # Delay before restart attempt N (the last entry repeats). The counter
    # resets after RESTART_FORGIVENESS seconds without a failure.
    RESTART_BACKOFF = [ 0, 5, 10, 30, 60, 300 ].freeze
    RESTART_FORGIVENESS = 600

    # Test seam: shortens the monitor's cadence.
    def monitor_interval = @monitor_interval || MONITOR_INTERVAL

    def monitor_interval=(seconds)
      @monitor_interval = seconds
    end

    def restart_backoff = @restart_backoff || RESTART_BACKOFF

    def restart_backoff=(delays)
      @restart_backoff = delays
    end

    # Starts one server per requested protocol, plus the monitor, and
    # returns the handles.
    def start_servers(protocols: MailOnRails.protocols)
      if defined?(Rails) && Rails.env.production?
        require_explicit_tls!(protocols)
        require_virus_scanner!
      end
      @handles = {}
      protocols.each { |protocol| @handles[protocol] = start_protocol(protocol) }
      start_monitor
      @handles
    end

    # Boots a single protocol's store + daemon. The monitor calls this
    # again when that protocol needs a restart.
    def start_protocol(protocol)
      case protocol
      when :imap
        require "mail_on_rails/imap/daemon"
        require "mail_on_rails/store/with_source"
        store = MailOnRails::Store::WithSource.new(MailOnRails::Store::ImapBackend.new, "imap")
        MailOnRails::Imap::Daemon.start(store: store, logger: MailOnRails.logger,
                                        tls_dir: MailOnRails.tls_dir)
      when :smtp
        require "mail_on_rails/smtp/daemon"
        require "mail_on_rails/store/smtp_backend"
        MailOnRails::Smtp::Daemon.start(store: MailOnRails::Store::SmtpBackend.new,
                                        logger: MailOnRails.logger, tls_dir: MailOnRails.tls_dir,
                                        hostname: method(:smtp_hostname))
      else
        raise ArgumentError, "unknown protocol #{protocol.inspect}"
      end
    end

    # True once every started server has all its listeners bound and none
    # of them has died. False before start_servers and after stop_servers -
    # a health check must not pass while the mail ports are down.
    def ready?
      handles = (@handles || {}).values
      handles.any? && handles.all? { |handle| handle.ready? && handle.server.healthy? }
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

    # The running server for :imap or :smtp - live-connection pages read
    # #connections (and #max_connections) off it. nil when that server
    # isn't running in this process (a boot without the Puma plugin, e.g.
    # tests or a web-only process).
    def server(protocol)
      (@handles || {})[protocol]&.server
    end

    # Drops live connections whose peer IP the caller's test matches, on
    # every running server (see Netserv::Server#kick). Used when an admin
    # bans an address: the denylists only silence future connections.
    # Returns how many connections were closed.
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

    # Production must never serve mail on the self-signed development
    # fallback: clients would either refuse the cert or train users to
    # click through warnings, and both failure modes look "up" from a
    # deploy's point of view. Each protocol reads its own cert/key pair
    # (the TLS modules fail closed on their own once these are set), so a
    # missing pair here fails the boot instead of quietly generating a
    # self-signed cert.
    def require_explicit_tls!(protocols)
      missing = []
      missing << "MAIL_ON_RAILS_TLS_CERT/MAIL_ON_RAILS_TLS_KEY" if protocols.include?(:imap) &&
        !(Settings.static(:imap_tls_cert) || Settings.static(:imap_tls_key))
      missing << "SMTP_TLS_CERT/SMTP_TLS_KEY" if protocols.include?(:smtp) &&
        !(Settings.static(:smtp_tls_cert) || Settings.static(:smtp_tls_key))
      return if missing.empty?

      raise "production requires explicit TLS material for the mail servers " \
            "(self-signed fallback is development-only): set #{missing.join(" and ")}"
    end

    # The schema default for SMTP_CLAMAV_ADDR is empty - right for
    # development, but in production it means a deploy that forgets one
    # env accepts and stores mail with no virus verdict, and nothing
    # visible breaks. Running unscanned must be a decision
    # (SMTP_CLAMAV_OPTIONAL=1), never a side effect of a missing env.
    def require_virus_scanner!
      return unless Settings[:smtp_clamav_addr].to_s.empty?
      return if Settings.static(:smtp_clamav_optional)

      raise "production requires a virus scanner: set SMTP_CLAMAV_ADDR to a clamd address " \
            "(the Kamal template uses mail_on_rails-clamav:3310), or explicitly opt out of " \
            "scanning with SMTP_CLAMAV_OPTIONAL=1"
    end

    # The name SMTP sessions announce, resolved per connection through the
    # host-provided callable (defaults to the Setting-backed lookup wired
    # by the engine). Falls back to the env/system name - the banner must
    # still go out.
    def smtp_hostname
      resolver = MailOnRails.smtp_hostname_resolver
      value = resolver&.call.to_s.strip
      return value unless value.empty?

      Settings.static(:smtp_helo_hostname) || Socket.gethostname
    end
  end
end
