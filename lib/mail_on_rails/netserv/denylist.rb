# frozen_string_literal: true

require "ipaddr"

module MailOnRails
  module Netserv
    # The admin ban list (the Rails app's BannedIp table), read through the
    # store's banned_cidrs so this layer stays Rails-free. Checked on the
    # accept path for every connection - and only ever against a frozen
    # in-memory snapshot there: the accept thread never asks the store and
    # never takes a lock, so a slow database can delay a ban's arrival but
    # never a banner. The snapshot is refreshed off the accept path:
    #
    #   - Server#run loads it once before the first accept (the store is
    #     fine to wait on at boot);
    #   - the listener's OpsSync tick calls pull, which re-reads the store
    #     once TTL seconds have passed since the last read, so a ban lands
    #     within a few seconds of the row committing;
    #   - in-process writers call refresh! (via MailOnRails.refresh_denylists)
    #     so a new ban applies to the very next connection.
    #
    # Fail-soft everywhere, like TLS::ContextProvider: a store without a
    # ban list means the feature is off (the vendored memory stores return
    # an empty list; a bare test double may lack the method entirely), a
    # store error keeps the last good list - dropping to "no bans" on a DB
    # hiccup would let banned peers straight back in - a garbled entry is
    # skipped, an unparseable peer address never matches.
    class Denylist
      TTL = 5 # seconds between store reads

      def initialize(store, ttl: TTL)
        @store = store.respond_to?(:banned_cidrs) ? store : nil
        @ttl = ttl
        # Serializes the refreshers (an ops tick and an after_commit may
        # coincide); readers never take it.
        @mutex = Mutex.new
        @networks = [].freeze
        @checked_at = nil
      end

      # Lock-free: reads whichever snapshot was last swapped in.
      def banned?(ip)
        return false if @store.nil? || ip.nil?

        addr = begin
          IPAddr.new(ip)
        rescue IPAddr::Error
          return false
        end
        # A v4-mapped peer ("::ffff:203.0.113.5", what a dual-stack socket
        # reports for IPv4 clients) is an IPv4 ban's business. The server
        # canonicalizes at accept; this repeats it so the gate never
        # depends on the caller having done so.
        addr = addr.native if addr.ipv4_mapped?
        @networks.any? { |net| net.ipv4? == addr.ipv4? && net.include?(addr) }
      end

      # Immediate reload, bypassing the TTL.
      def refresh!
        return if @store.nil?

        @mutex.synchronize { load_networks }
        nil
      end

      # Reload if TTL seconds have passed since the last store read (the
      # OpsSync tick's call). Returns true when it read the store.
      def pull
        return false if @store.nil?

        @mutex.synchronize do
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return false unless @checked_at.nil? || now - @checked_at >= @ttl

          load_networks
          true
        end
      end

      private

      # Holds @mutex. Anything but an array of entries - the error hash
      # Store::Base#db returns, or a raise from a store without its own
      # rescue - keeps the last good list (and the TTL stamp, so a down
      # database is retried once per TTL, not per tick). The parsed list
      # is built aside and swapped in whole: readers see the old snapshot
      # or the new one, never a half-built one.
      def load_networks
        @checked_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        cidrs = begin
          @store.banned_cidrs
        rescue StandardError
          nil
        end
        return unless cidrs.is_a?(Array)

        @networks = cidrs.filter_map do |entry|
          IPAddr.new(entry.to_s)
        rescue IPAddr::Error
          nil
        end.freeze
      end
    end
  end
end
