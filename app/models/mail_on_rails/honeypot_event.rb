# A honeypot hit: an interaction that only an attacker would have (TRIGGERS):
# a successful login against a canary account (an EmailAccount flagged
# honeypot: true, which no real user owns), an exploit-probe payload thrown at
# any listener (an Exim ${run{...} substitution, a shellshock preamble, VRFY
# root, ...), another protocol spoken at a mail port (an HTTP request line, an
# SSH banner, a TLS ClientHello on a plaintext port), or garbage bytes no mail
# command contains. All are hostile, so every row is signal - but a stranger
# still sets the growth rate (one probe line and then a session of NOOPs is
# a 128 KiB transcript and a DNS job, per connection, all day), so like
# AuthAttempt and ClosedConnection the table is capped per source: past
# honeypot_max_events_per_ip hits from one address (IPv6: one /64) inside
# honeypot_cap_window, further hits are answered by the session as before
# but not stored, and the last stored row says so in its response.
#
# Written from the protocol sessions' honeypot path through
# Store::Base#record_honeypot_event (best-effort, respond_to?-guarded like
# record_closed_connection). Creating a row triggers a graduated,
# multi-tenant-safe response (apply_response) and fills in DNS attribution -
# from the IpEnrichment cache when it already knows the address, otherwise
# through a job off the connection thread.
#
# By default the response is never an automatic permanent ban - on a shared
# server a permanent IP block is collateral damage waiting to happen (CGNAT,
# VPN and corporate NATs put many real tenants behind one address). Instead:
#
#   canary_auth      - near-zero false positive, so a *temporary*, auto-expiring
#                      IP throttle (AuthThrottle), but only when the address is
#                      neither allowlisted nor carrying recent legitimate tenant
#                      traffic (a real account authenticating from the same IP
#                      marks it shared, and it is left alone).
#   exploit_probe,
#   foreign_protocol,
#   garbage          - recorded only; an admin escalates by hand from the
#                      dashboard (a permanent BannedIp, or a live kick).
#
# An operator who would rather not review scanner noise switches
# protocol_auto_ban on: the three probe-type triggers then write the same
# permanent BannedIp a failed login does under auth_auto_ban. The exceptions
# are the honeypot allowlist and BannedIp.probe_ban_exemption - a local
# address (behind a proxy it is everyone) or one that logged in or delivered
# mail lately: a probe signature is a regex, and a third party's MX relaying
# a message to an RFC-legal but exploit-shaped quoted local-part matches it
# too. The action taken is stored in `response` so the dashboard is honest
# about what happened.
#
# The transcript is the full redacted wire dialogue of the session. Passwords -
# the canary's own and anything the attacker typed - are redacted at the tap,
# the same policy AuthAttempt keeps: what an attacker sends is dictionary noise
# and a liability, what they *do* (FETCH/SEARCH/relay envelopes) is the intel.
require "mail_on_rails/netserv/ip"

module MailOnRails
  class HoneypotEvent < Record
    TRIGGERS = %w[canary_auth exploit_probe foreign_protocol garbage].freeze
    # The triggers protocol_auto_ban acts on: everything but a canary login.
    PROBE_TRIGGERS = (TRIGGERS - %w[canary_auth]).freeze
    PROTOCOLS = %w[smtp imap].freeze
    # Appended to the response of the last row stored for a source inside
    # a capped window, so the dashboard shows where the record stops.
    CAP_MARKER = "(cap reached: later hits this window not stored)"

    scope :recent, ->(since) { where(occurred_at: since..) }

    validates :protocol, inclusion: { in: PROTOCOLS }
    validates :trigger, inclusion: { in: TRIGGERS }

    after_create_commit :apply_response
    after_create_commit :enqueue_enrichment

    class << self
      def retention_days = MailOnRails::Settings[:honeypot_retention_days]

      # How long a canary-triggered temporary IP throttle lasts.
      def block_seconds = MailOnRails::Settings[:honeypot_block_seconds]

      # How far back a legitimate authenticated connection from an IP still
      # marks it "shared" and off-limits for an automatic block.
      def collateral_days = MailOnRails::Settings[:honeypot_collateral_days]

      # Whether probe-type hits ban their source permanently.
      def protocol_auto_ban? = MailOnRails::Settings[:protocol_auto_ban]

      # Rows one source may insert per cap window before its further hits
      # go unrecorded, and that window.
      def max_events_per_ip = MailOnRails::Settings[:honeypot_max_events_per_ip]
      def cap_window = MailOnRails::Settings[:honeypot_cap_window]

      # Never-touch source addresses (own monitoring, health checks, known
      # relays): comma/space-separated CIDRs.
      def allowlist_networks
        MailOnRails::Settings[:honeypot_allowlist].filter_map do |cidr|
          IPAddr.new(cidr)
        rescue IPAddr::Error
          nil
        end
      end

      def allowlisted?(ip)
        addr = IPAddr.new(ip.to_s)
        allowlist_networks.any? { |net| net.include?(addr) }
      rescue IPAddr::Error
        false
      end

      # "Is a real tenant behind this address?" A non-canary account closing an
      # authenticated connection from this IP recently marks it shared, so a
      # single attacker behind it must not get the whole address blocked. Reads
      # ClosedConnection's notable (authenticated) history - no new bookkeeping.
      # The block that follows lands on the throttle key (the /64 for IPv6),
      # so the collateral question is asked of the whole key: a tenant
      # anywhere in the same /64 makes it shared.
      def legitimate_traffic_from?(ip)
        return false if ip.blank?

        scope = ClosedConnection.where.not(username: nil).where(closed_at: collateral_days.days.ago..)
        canaries = EmailAccount.honeypots.pluck(:email)
        scope = scope.where.not(username: canaries) if canaries.any?
        # By address as well as by key: rows written before throttle_key
        # existed carry only the address.
        scope.where(ip: ip).or(scope.where(throttle_key: Netserv.throttle_key(ip))).exists?
      end

      # Records one honeypot hit from the payload the session assembles, or
      # nothing once the source is past its cap (the session then has no
      # event id, so its teardown transcript flush is skipped too). Never
      # raises: this runs on a live connection thread, and losing an intel
      # row is always better than disturbing the session.
      def record(info)
        info = info.symbolize_keys
        ip = Netserv.canonical_ip(info[:ip].presence)
        now = info[:occurred_at] || Time.current
        return note_cap_reached(ip, now) unless under_cap?(ip, now)

        create!(protocol: info[:protocol].to_s, trigger: info[:trigger].to_s,
                signature: info[:signature].presence, ip: ip,
                port: info[:port], username: info[:username].presence,
                helo: info[:helo].presence, transcript: info[:transcript].to_s,
                occurred_at: now)
      rescue StandardError => e
        Rails.logger.error("[mail_on_rails] honeypot event failed: #{e.class}: #{e.message}")
        nil
      end

      # Whether +ip+ may still store a row in the cap window ending at +now+.
      def under_cap?(ip, now)
        return true if ip.blank?

        cap_scope(ip).where(occurred_at: (now - cap_window)..now).count < max_events_per_ip
      end

      # The rows that count toward +ip+'s cap. IPv4: the address. IPv6:
      # the /64, like every other per-source control - but this table
      # stores only the full address, so the /64 is matched on the
      # address's canonical spelling: the network's leading non-zero
      # groups are printed verbatim in every member's compressed form
      # (compression only ever swallows zero groups), so a LIKE on that
      # prefix finds them all. A network whose prefix contains a zero
      # group gets a coarser prefix and so counts its neighbourhood in
      # with itself; that only makes the cap bite sooner, never later.
      def cap_scope(ip)
        addr = IPAddr.new(ip.to_s)
        addr = addr.native if addr.ipv4_mapped?
        return where(ip: addr.to_s) if addr.ipv4?

        groups = addr.mask(64).to_string.split(":").first(4)
        leading = groups.take_while { |group| group != "0000" }.map { |group| group.to_i(16).to_s(16) }
        prefix = leading.empty? ? "" : "#{leading.join(':')}:"
        where(arel_table[:ip].matches("#{sanitize_sql_like(prefix)}%", nil, true))
      rescue IPAddr::Error
        where(ip: ip.to_s)
      end

      def prune!(now: Time.current)
        where(occurred_at: ...(now - retention_days.days)).delete_all
      end

      private

      # Past the cap: nothing is stored, but the newest row the source did
      # get in this window carries the marker once, so the dashboard shows
      # the record stopped rather than the source going quiet. One read
      # per suppressed hit, one write per window.
      def note_cap_reached(ip, now)
        row = cap_scope(ip).where(occurred_at: (now - cap_window)..now)
                           .order(occurred_at: :desc, id: :desc).select(:id, :ip, :response).first
        return nil if row.nil? || row.response.to_s.include?(CAP_MARKER)

        row.update_column(:response, "#{row.response} #{CAP_MARKER}".strip)
        Rails.logger.info("[mail_on_rails] honeypot events from #{Netserv.throttle_key(ip)} capped at " \
                          "#{max_events_per_ip} per #{cap_window}s; further hits are not stored")
        nil
      end
    end

    private

    # The graduated response (see the class comment). Records what it did in
    # `response`; best-effort, so a response failure never breaks the event
    # write. Never kicks the live session (a ban reaches it on the next ops
    # tick); a permanent ban only under protocol_auto_ban.
    def apply_response
      update_column(:response, decide_response)
    rescue StandardError => e
      Rails.logger.error("[mail_on_rails] honeypot response failed: #{e.class}: #{e.message}")
    end

    def decide_response
      return "observed" if ip.blank?
      return "allowlisted" if self.class.allowlisted?(ip)
      return probe_response if PROBE_TRIGGERS.include?(trigger)
      return "observed (shared address)" if self.class.legitimate_traffic_from?(ip)

      # block_ip! keys on the throttle key itself (the /64 for IPv6); the
      # full address stays on this row for the dashboard.
      MailOnRails::AuthThrottle.block_ip!(ip, seconds: self.class.block_seconds)
      "throttled #{self.class.block_seconds / 60}m"
    end

    # Probes are observe-only unless protocol_auto_ban is on: too much
    # false-positive/collateral risk to act on a regex automatically without
    # the operator having chosen it. Once chosen, the collateral checks
    # BannedIp.probe_ban_exemption makes (local or working address) still
    # hold - the response names the reason so the dashboard is honest.
    def probe_response
      return "observed" unless self.class.protocol_auto_ban?
      if (reason = MailOnRails::BannedIp.probe_ban_exemption(ip, now: occurred_at || Time.current))
        return "observed (#{reason})"
      end

      if (row = MailOnRails::BannedIp.auto_ban_for_probe(ip: ip, protocol: protocol, trigger: trigger,
                                                          signature: signature))
        "banned #{row.cidr}"
      elsif MailOnRails::BannedIp.covering(ip)
        "already banned"
      else
        "observed"
      end
    end

    # Attribution from the IpEnrichment cache when it is fresh (one indexed
    # read; a scanner's second hit costs no DNS at all), otherwise a job.
    def enqueue_enrichment
      return if ip.blank?

      if (cached = IpEnrichment.cached(ip))
        update_column(:enrichment, cached)
      else
        HoneypotEnrichmentJob.perform_later(id)
      end
    rescue StandardError => e
      Rails.logger.error("[mail_on_rails] honeypot enrichment failed: #{e.class}: #{e.message}")
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_honeypot_event, MailOnRails::HoneypotEvent
