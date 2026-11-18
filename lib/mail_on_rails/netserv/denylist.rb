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
    #
    # An automatic ban setting lets strangers add rows, so neither the
    # lookup nor the refresh may cost in proportion to the list:
    #
    #   - the snapshot is keyed by prefix: per address family, one set of
    #     masked networks for each prefix length that occurs. A lookup
    #     masks the peer once per length present (a handful: /32, /24s
    #     and DROP's ranges for IPv4; /64, /48, /32 for IPv6) and probes
    #     a hash - the same cost at ten rows and at a hundred thousand;
    #   - a pull first asks the store for a cheap fingerprint of the list
    #     (banned_cidrs_stamp, when it has one) and reads nothing more
    #     while that is unchanged; a list that did change is re-read, but
    #     only entries not seen last time are parsed.
    class Denylist
      TTL = 5 # seconds between store reads

      # A parsed snapshot: for IPv4 and IPv6 each, { host bits => set of
      # networks shifted down by that many bits }.
      Index = Struct.new(:v4, :v6) do
        def self.empty = new({}.freeze, {}.freeze).freeze
      end

      def initialize(store, ttl: TTL)
        @store = store.respond_to?(:banned_cidrs) ? store : nil
        @ttl = ttl
        # Serializes the refreshers (an ops tick and an after_commit may
        # coincide); readers never take it.
        @mutex = Mutex.new
        @index = Index.empty
        # Refresher state, all under @mutex: the list as last read, each
        # entry's parsed form, and the store's fingerprint from that read.
        @cidrs = [].freeze
        @parsed = {}
        @stamp = nil
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
        index = @index
        value = addr.to_i
        (addr.ipv4? ? index.v4 : index.v6).any? { |host_bits, networks| networks.include?(value >> host_bits) }
      end

      # Immediate reload, bypassing the TTL (and the fingerprint: the
      # caller knows the list changed).
      def refresh!
        return if @store.nil?

        @mutex.synchronize { load_networks(force: true) }
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
      # database is retried once per TTL, not per tick). The index is
      # built aside and swapped in whole: readers see the old snapshot or
      # the new one, never a half-built one.
      def load_networks(force: false)
        @checked_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        # Read BEFORE the list, so the list is never older than the
        # fingerprint kept with it: a row committed in between costs one
        # extra reload next time, never a missed one.
        stamp = store_stamp
        return if !force && !stamp.nil? && stamp == @stamp

        cidrs = begin
          @store.banned_cidrs
        rescue StandardError
          nil
        end
        return unless cidrs.is_a?(Array)

        @stamp = stamp
        return if cidrs == @cidrs

        parsed = {}
        cidrs.each do |entry|
          key = entry.to_s
          parsed[key] = @parsed.fetch(key) { parse(key) }
        end
        @index = build_index(parsed.each_value)
        @parsed = parsed
        @cidrs = cidrs.dup.freeze
      end

      # The store's fingerprint of its ban list, or nil when it has none
      # to offer (a memory store, a database error) - nil always means
      # "read the list".
      def store_stamp
        return nil unless @store.respond_to?(:banned_cidrs_stamp)

        stamp = @store.banned_cidrs_stamp
        stamp.is_a?(Array) ? stamp : nil
      rescue StandardError
        nil
      end

      # [ ipv4?, host bits, network >> host bits ], or nil for a garbled
      # entry (kept in the parse cache as nil, so it is not retried on
      # every reload).
      def parse(entry)
        net = IPAddr.new(entry)
        host_bits = (net.ipv4? ? 32 : 128) - net.prefix
        [ net.ipv4?, host_bits, net.to_i >> host_bits ]
      rescue IPAddr::Error
        nil
      end

      def build_index(entries)
        v4 = {}
        v6 = {}
        entries.each do |ipv4, host_bits, network|
          next if host_bits.nil?

          ((ipv4 ? v4 : v6)[host_bits] ||= {})[network] = true
        end
        [ v4, v6 ].each { |table| table.each_value(&:freeze) }
        Index.new(v4.freeze, v6.freeze).freeze
      end
    end
  end
end
