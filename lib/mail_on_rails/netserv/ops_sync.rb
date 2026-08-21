# frozen_string_literal: true

require "socket"
require "securerandom"
require_relative "../settings"

module MailOnRails
  module Netserv
    # One background thread per Netserv::Server that keeps the database's
    # picture of this listener current and carries commands back, so the
    # admin UI works identically whether the listener runs inside the web
    # process or in another container. Every Settings[:ops_sync_interval]
    # seconds (default 2) it:
    #
    # 1. snapshots Server#connections and #lockouts; if that picture
    #    changed since the last tick, writes it through the store
    #    (sync_ops_state) and THEN fires MailOnRails.on_connection_activity
    #    - the dashboard refresh never races the rows it announces;
    #    unchanged, it only heartbeats the listener row;
    # 2. kicks live sessions whose peer the store's denylist now bans - a
    #    BannedIp row is the command, no separate kick needed - and those
    #    named by pending ConnectionKick rows (honeypot kick), acking each
    #    with the count;
    # 3. sweeps the projections of listeners whose heartbeat went stale
    #    (a killed container that never ran its shutdown).
    #
    # Nothing here runs on the accept path or a connection thread: the
    # snapshot costs one lock acquisition per tick, the writes are a
    # handful of statements bounded by the connection cap, and every store
    # call is best-effort. A store without the ops methods (the memory
    # stores, Rails-free runs) still gets the tick's change detection and
    # the activity hook - that keeps the hook's contract (and the protocol
    # suites) independent of a database.
    class OpsSync
      DEFAULT_INTERVAL = 2.0
      DEFAULT_STALE_AFTER = 30

      attr_reader :listener_id, :started_at

      def initialize(server, store, interval: nil, stale_after: nil)
        @server = server
        @store = store
        # The protocol label ("SMTP"/"IMAP") - private on the servers, and
        # resolved once here (the base Server has none).
        @protocol_label = server.respond_to?(:protocol_name, true) ? server.send(:protocol_name).to_s : "mail"
        @interval = interval
        @stale_after = stale_after
        @listener_id = SecureRandom.uuid
        @started_at = Time.now
        @connection_seq = 0
        @seq_mutex = Mutex.new
        @mutex = Mutex.new
        @cv = ConditionVariable.new
        @stop = false
        # The empty picture: the first tick announces nothing unless a
        # connection or lockout already exists.
        @last_digest = picture_digest([], {})
        @thread = nil
      end

      # Monotonic per-listener connection ids (the open_connections row
      # key alongside listener_id).
      def next_connection_id
        @seq_mutex.synchronize { @connection_seq += 1 }
      end

      def start
        return if @thread

        @stop = false
        @thread = Thread.new do
          Thread.current.name = "mail_on_rails_ops_#{@protocol_label.downcase}"
          loop do
            @mutex.synchronize { @cv.wait(@mutex, interval) unless @stop }
            break if @stop
            # A server whose listeners all died without a shutdown (a test
            # harness killing the run thread) must not keep ticking.
            break if @server.respond_to?(:dead?) && @server.dead?

            tick
          end
          cleanup
        end
      end

      # Signals the thread, waits briefly for its final tick/cleanup.
      def stop(timeout: 5)
        thread = @thread
        return unless thread

        @mutex.synchronize do
          @stop = true
          @cv.broadcast
        end
        thread.join(timeout) unless thread == Thread.current
        @thread = nil
      end

      # One pass; public so tests can drive it without the thread. Every
      # step is isolated: a failing store call must neither abort the
      # others nor kill the thread.
      def tick
        sync_picture
        kick_banned
        process_kicks
        sweep_stale
      end

      # The tick cadence, resolved per tick so a settings change applies
      # without a restart; never below 0.05s (a zero would spin).
      def interval
        value = @interval || Settings[:ops_sync_interval]
        value = value.call if value.respond_to?(:call)
        [ value.to_f, 0.05 ].max
      rescue StandardError
        DEFAULT_INTERVAL
      end

      def stale_after
        value = @stale_after || Settings[:ops_stale_after]
        value = value.call if value.respond_to?(:call)
        [ value.to_f, interval * 3 ].max
      rescue StandardError
        DEFAULT_STALE_AFTER
      end

      private

      def sync_picture
        connections = @server.connections
        lockouts = lockouts_as_deadlines(@server.lockouts)
        digest = picture_digest(connections, lockouts)
        changed = digest != @last_digest
        @last_digest = digest

        if @store.respond_to?(:sync_ops_state)
          @store.sync_ops_state(listener: listener_row,
                                connections: changed ? connections : nil,
                                lockouts: changed ? lockouts : nil)
        end
        @server.notify_activity if changed
      rescue StandardError => e
        warn_once(:sync, e)
      end

      # Live sessions whose peer is now on the admin ban list: the
      # denylist only silences future accepts, so the ban's "drop what is
      # open" half happens here. Denylist#banned? refreshes from the store
      # on its own TTL, so an idle listener still notices a new ban.
      def kick_banned
        denylist = @server.denylist
        return unless denylist

        kicked = @server.kick { |ip| denylist.banned?(ip) }
        @store.log(:info, "#{@protocol_label} dropped #{kicked} connection(s) from banned addresses") if kicked.positive?
      rescue StandardError => e
        warn_once(:kick_banned, e)
      end

      def process_kicks
        return unless @store.respond_to?(:pending_kicks)

        kicks = @store.pending_kicks(@protocol_label.downcase)
        return unless kicks.is_a?(Array)

        kicks.each do |kick|
          target = kick[:ip].to_s
          count = @server.kick { |ip| ip == target }
          @store.ack_kick(kick[:id], kicked: count, processed_by: @listener_id)
          @store.log(:info, "#{@protocol_label} kick #{target}: dropped #{count} connection(s)")
        end
      rescue StandardError => e
        warn_once(:process_kicks, e)
      end

      def sweep_stale
        return unless @store.respond_to?(:prune_stale_listeners)

        @store.prune_stale_listeners(stale_after)
      rescue StandardError => e
        warn_once(:sweep, e)
      end

      def cleanup
        @store.remove_listener(@listener_id) if @store.respond_to?(:remove_listener)
      rescue StandardError => e
        warn_once(:cleanup, e)
      end

      def listener_row
        {
          listener_id: @listener_id,
          protocol: @protocol_label.downcase,
          pid: Process.pid,
          hostname: hostname,
          ports: @server.listener_ports,
          max_connections: @server.max_connections,
          ready: @server.ready?,
          started_at: @started_at
        }
      end

      # What "the picture changed" compares: connections and lockouts as
      # plain values (readiness is heartbeated on the listener row every
      # tick regardless, and must not announce itself as activity).
      def picture_digest(connections, lockouts)
        [ connections, lockouts ].hash
      end

      # { ip => seconds remaining } -> { ip => locked_until }, rounded to
      # the second so a countdown does not read as a change every tick.
      def lockouts_as_deadlines(remaining_by_ip)
        now = Time.now
        remaining_by_ip.to_h { |ip, seconds| [ ip, Time.at((now + seconds.to_f).to_i) ] }
      end

      def hostname
        @hostname ||= Socket.gethostname
      rescue StandardError
        @hostname = nil
      end

      # Log each failing step once per distinct message, not every tick -
      # a database outage must not turn the ops thread into a log flood.
      def warn_once(step, error)
        key = "#{step}:#{error.class}:#{error.message}"
        @warned ||= {}
        return if @warned[key]

        @warned[key] = true
        @store.log(:warn, "#{@protocol_label} ops sync #{step} failed: #{error.class}: #{error.message}")
      rescue StandardError
        nil
      end
    end
  end
end
