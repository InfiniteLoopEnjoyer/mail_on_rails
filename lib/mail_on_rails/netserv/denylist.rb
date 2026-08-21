# frozen_string_literal: true

require "ipaddr"

module MailOnRails
  module Netserv
    # The admin ban list (the Rails app's BannedIp table), read through the
    # store's banned_cidrs so this layer stays Rails-free. Checked on the
    # accept path for every connection; the store is asked at most once per
    # TTL seconds and the parsed networks cached in between, so a ban lands
    # within seconds of the row committing without a query per connection
    # under load. In-process writers also call refresh! (via
    # MailOnRails.refresh_denylists) so a new ban applies to the very next
    # connection.
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
        @mutex = Mutex.new
        @networks = []
        @checked_at = nil
      end

      def banned?(ip)
        return false if @store.nil? || ip.nil?

        addr = begin
          IPAddr.new(ip)
        rescue IPAddr::Error
          return false
        end
        current_networks.any? { |net| net.ipv4? == addr.ipv4? && net.include?(addr) }
      end

      # Immediate reload, bypassing the TTL.
      def refresh!
        return if @store.nil?

        @mutex.synchronize { load_networks }
        nil
      end

      private

      def current_networks
        @mutex.synchronize do
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          load_networks if @checked_at.nil? || now - @checked_at >= @ttl
          @networks
        end
      end

      # Holds @mutex. Anything but an array of entries - the error hash
      # Store::Base#db returns, or a raise from a store without its own
      # rescue - keeps the last good list (and the TTL stamp, so a down
      # database is retried once per TTL, not per connection).
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
        end
      end
    end
  end
end
