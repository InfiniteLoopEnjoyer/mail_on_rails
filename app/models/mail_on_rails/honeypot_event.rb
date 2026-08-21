# A honeypot hit: an interaction that only an attacker would have. Two kinds
# today (TRIGGERS): a successful login against a canary account (an EmailAccount
# flagged honeypot: true, which no real user owns), and an exploit-probe
# payload thrown at any listener (an Exim ${run{...} substitution, a shellshock
# preamble, VRFY root, ...). Both are unambiguously hostile, so unlike
# AuthAttempt/ClosedConnection this table needs no rollup - every row is signal.
#
# Written from the protocol sessions' honeypot path through
# Store::Base#record_honeypot_event (best-effort, respond_to?-guarded like
# record_closed_connection). Creating a row triggers a graduated,
# multi-tenant-safe response (apply_response) and enqueues DNS enrichment off
# the connection thread.
#
# The response is deliberately never an automatic permanent ban - on a shared
# server a permanent IP block is collateral damage waiting to happen (CGNAT,
# VPN and corporate NATs put many real tenants behind one address). Instead:
#
#   canary_auth   - near-zero false positive, so a *temporary*, auto-expiring
#                   IP throttle (AuthThrottle), but only when the address is
#                   neither allowlisted nor carrying recent legitimate tenant
#                   traffic (a real account authenticating from the same IP
#                   marks it shared, and it is left alone).
#   exploit_probe - a regex match, higher false-positive and collateral risk,
#                   so recorded only. An admin escalates it by hand from the
#                   dashboard (a permanent BannedIp, or a live kick).
#
# The action taken is stored in `response` so the dashboard is honest about
# what happened, and a permanent ban stays a human decision.
#
# The transcript is the full redacted wire dialogue of the session. Passwords -
# the canary's own and anything the attacker typed - are redacted at the tap,
# the same policy AuthAttempt keeps: what an attacker sends is dictionary noise
# and a liability, what they *do* (FETCH/SEARCH/relay envelopes) is the intel.
module MailOnRails
  class HoneypotEvent < Record
    TRIGGERS = %w[canary_auth exploit_probe].freeze
    PROTOCOLS = %w[smtp imap].freeze

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
      def legitimate_traffic_from?(ip)
        return false if ip.blank?

        scope = ClosedConnection.where(ip: ip).where.not(username: nil)
                                .where(closed_at: collateral_days.days.ago..)
        canaries = EmailAccount.honeypots.pluck(:email)
        scope = scope.where.not(username: canaries) if canaries.any?
        scope.exists?
      end

      # Records one honeypot hit from the payload the session assembles. Never
      # raises: this runs on a live connection thread, and losing an intel row
      # is always better than disturbing the session.
      def record(info)
        info = info.symbolize_keys
        create!(protocol: info[:protocol].to_s, trigger: info[:trigger].to_s,
                signature: info[:signature].presence, ip: info[:ip].presence,
                port: info[:port], username: info[:username].presence,
                helo: info[:helo].presence, transcript: info[:transcript].to_s,
                occurred_at: info[:occurred_at] || Time.current)
      rescue StandardError => e
        Rails.logger.error("[mail_on_rails] honeypot event failed: #{e.class}: #{e.message}")
        nil
      end

      def prune!(now: Time.current)
        where(occurred_at: ...(now - retention_days.days)).delete_all
      end
    end

    private

    # The graduated response (see the class comment). Records what it did in
    # `response`; best-effort, so a response failure never breaks the event
    # write. Never bans permanently and never kicks the live session - those
    # stay human decisions on the dashboard.
    def apply_response
      update_column(:response, decide_response)
    rescue StandardError => e
      Rails.logger.error("[mail_on_rails] honeypot response failed: #{e.class}: #{e.message}")
    end

    def decide_response
      return "observed" if ip.blank?
      return "allowlisted" if self.class.allowlisted?(ip)
      # Probes are observe-only: too much false-positive/collateral risk to act
      # on a regex automatically. The admin escalates from the dashboard.
      return "observed" unless trigger == "canary_auth"
      return "observed (shared address)" if self.class.legitimate_traffic_from?(ip)

      MailOnRails::AuthThrottle.block_ip!(ip, seconds: self.class.block_seconds)
      "throttled #{self.class.block_seconds / 60}m"
    end

    def enqueue_enrichment
      HoneypotEnrichmentJob.perform_later(id) if ip.present?
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_honeypot_event, MailOnRails::HoneypotEvent
