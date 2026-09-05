# frozen_string_literal: true

require_relative "../settings"

module MailOnRails
  module Settings
    # Configuration validation report for the CLI's `check` command
    # (solid_queue's Configuration#check shape): collects every problem
    # instead of stopping at the first, separates fatal errors from
    # suspicious-but-runnable warnings, and never binds a socket.
    #
    # Errors: any declared ENV variable that fails to parse, and (via the
    # daemons' check_config, which the CLI runs alongside this) colliding
    # ports or unusable TLS material. Warnings: boolean spellings that
    # read as set-but-inert ("true"/"yes"/"off" - each has caused a quiet
    # runtime surprise), sender verification disabled, and - when the
    # database tier is reachable - settings rows the schema cannot type.
    class Check
      # Past a week, a raised seal lifetime is a forgotten override, not a
      # backlog recovery (the default is 6h).
      SEAL_MAX_AGE_UNUSUAL = 7 * 86_400

      attr_reader :errors, :warnings

      def initialize
        @errors = []
        @warnings = []
        check_env
        check_boolean_spellings
        check_sender_auth
        check_production_posture
        check_db_rows
      end

      def ok? = @errors.empty?

      # Prints the report; returns ok?.
      def report(io = $stdout)
        @warnings.each { |warning| io.puts "warning: #{warning}" }
        @errors.each { |error| io.puts "error: #{error}" }
        ok?
      end

      private

      def check_env
        Settings.definitions.each do |definition|
          definition.env_value
        rescue StandardError => e
          @errors << e.message
        end
      end

      # The legacy boolean variables are deliberately asymmetric (a
      # default-on switch is disabled only by "0", a default-off switch
      # is enabled only by "1"); the common spellings that silently do
      # nothing deserve a callout, not silence.
      def check_boolean_spellings
        Settings.definitions.each do |definition|
          next unless definition.type == :boolean && definition.env

          raw = ENV[definition.env]
          next if raw.nil?

          if definition.default && raw != "0" && raw.match?(/\A(false|no|off|disabled)\z/i)
            @warnings << "#{definition.env}=#{raw} does NOT disable #{definition.name} - only \"0\" does"
          elsif !definition.default && raw != "1" && raw.match?(/\A(true|yes|on|enabled)\z/i)
            @warnings << "#{definition.env}=#{raw} does NOT enable #{definition.name} - only \"1\" does"
          end
        end
      end

      def check_sender_auth
        return if Settings[:smtp_sender_auth]

        @warnings << "sender authentication is off - inbound mail is accepted " \
                     "without SPF/DKIM/DMARC verification"
      rescue StandardError
        nil # an env error here is already reported by check_env
      end

      # Production posture: the schema defaults enforce (verified TLS,
      # DMARC, MTA-STS enforce, rspamd fail-closed), so these fire only
      # where a deployment has weakened one - each weakening is legitimate
      # while a soak runs, and this is the reminder that it is still in
      # place. Only meaningful with Rails in the process (the CLI boots
      # the host app); each item rescues independently so one bad env
      # can't mask the rest.
      def check_production_posture
        return unless defined?(Rails) && Rails.env.production?

        posture_warning do
          if !Settings[:smtp_dmarc_enforce] && !%w[enforce 1].include?(Settings[:mailroom_dmarc_enforce])
            "DMARC is not enforced at the SMTP edge or in the mailroom - mail failing " \
              "p=reject lands in INBOX (the defaults enforce; remove the SMTP_DMARC_ENFORCE=0 / " \
              "MAILROOM_DMARC_ENFORCE=log overrides once soak is clean)"
          end
        end
        posture_warning do
          unless Settings[:smtp_outbound_require_verified_tls]
            "outbound TLS is opportunistic and unverified - unless the destination publishes " \
              "DANE or MTA-STS enforce, mail can go out in the clear or to any certificate " \
              "(the default requires verified TLS; remove the SMTP_OUTBOUND_REQUIRE_VERIFIED_TLS=0 " \
              "override once TLS-RPT is clean)"
          end
        end
        posture_warning do
          if Settings.static(:mta_sts_mode) == "testing"
            "published MTA-STS policy mode is testing - remote senders will not enforce TLS " \
              "to this host (the default is enforce; return MAIL_ON_RAILS_MTA_STS_MODE to it " \
              "once TLS-RPT is clean)"
          end
        end
        posture_warning do
          if !Settings[:smtp_rspamd_addr].to_s.empty? && !Settings[:smtp_rspamd_fail_closed]
            "an rspamd outage lets authenticated submission through unscored " \
              "(the default refuses; remove the SMTP_RSPAMD_FAIL_CLOSED=0 override)"
          end
        end
        # The Password header rides on every rspamd request: the worker's
        # /checkv2 and the controller's /learnspam,/learnham alike.
        %i[smtp_rspamd_addr smtp_rspamd_controller_addr].each do |name|
          posture_warning do
            addr = Settings[name].to_s
            if !Settings.static(:smtp_rspamd_password).to_s.empty? &&
               !addr.empty? && !addr.start_with?("https://") &&
               !%w[localhost 127. ::1].any? { |local| addr.sub(%r{\Ahttps?://}, "").start_with?(local) }
              "the rspamd controller password travels over cleartext HTTP to #{addr} (#{name}) - " \
                "use https:// or a loopback address"
            end
          end
        end
        posture_warning do
          # "::" is the dual-stack spelling of the same exposure (IPv6 and
          # v4-mapped IPv4 on every interface).
          exposed = %i[smtp_host imap_host].select { |name| %w[0.0.0.0 ::].include?(Settings.static(name)) }
          unless exposed.empty?
            "#{exposed.join(" and ")} bind all interfaces (0.0.0.0 / ::) - confirm firewalling, " \
              "or bind explicitly via SMTP_HOST / MAIL_ON_RAILS_HOST"
          end
        end
        posture_warning do
          unless Settings[:mailroom_require_seal]
            "the mailroom accepts unsealed inbound email - trusted routing/auth headers are " \
              "unauthenticated (remove the MAILROOM_REQUIRE_SEAL=0 opt-out once the sealing " \
              "deploy has soaked)"
          end
        end
        posture_warning do
          if Settings[:smtp_sender_auth] && Settings[:smtp_dmarc_enforce] && !Settings[:smtp_sender_auth_fail_closed]
            "DMARC evaluation fails open on transient DNS errors - a DNS outage is a spoofing " \
              "window (the default fails closed; remove the SMTP_SENDER_AUTH_FAIL_CLOSED=0 override)"
          end
        end
        posture_warning do
          if Settings[:smtp_rbl_zones].empty?
            "no DNSBL zones are configured (SMTP_RBLS) - unauthenticated inbound from known-spam " \
              "IPs reaches DATA and is only junk-filed after acceptance"
          end
        end
        posture_warning do
          unless Settings[:smtp_from_alignment]
            "authenticated submissions may claim any From: header (the default requires the " \
              "account or one of its aliases; remove the SMTP_FROM_ALIGNMENT=0 override)"
          end
        end
        posture_warning do
          if !Settings.static(:smarthost_user).to_s.empty? && Settings.static(:smarthost_tls) == "opportunistic" &&
             !Settings[:smtp_outbound_require_verified_tls]
            "smarthost AUTH is disabled: credentials are configured but opportunistic mode does " \
              "not verify TLS, so they are withheld (MAIL_ON_RAILS_SMARTHOST_TLS=starttls or smtps)"
          end
        end
        posture_warning do
          if Settings[:smtp_clamav_addr].to_s.empty?
            "virus scanning is off (SMTP_CLAMAV_ADDR is empty) - inbound mail is accepted " \
              "at the MX and IMAP APPENDs are stored without a clamd verdict (the mail " \
              "servers refuse to boot like this in production unless SMTP_CLAMAV_OPTIONAL=1)"
          end
        end
        # The per-IP caps, lockouts, rates, send quota and session
        # lifetimes carry min: 1 in the schema, so a 0 is a check_env
        # error (ENV) or an unusable row (check_db_rows) rather than a
        # posture warning here.
        posture_warning do
          unless Settings[:imap_append_fail_closed]
            "IMAP APPEND stores mail unscanned while the virus scanner is unreachable " \
              "(the default refuses, like the SMTP edge's 451; remove the " \
              "MAIL_ON_RAILS_IMAP_APPEND_FAIL_CLOSED=0 override once the scanner is stable)"
          end
        end
        posture_warning do
          unless Settings[:mta_sts]
            "recipient MTA-STS policies are ignored on delivery - a domain that publishes " \
              "enforce still gets whatever TLS the path offers (the default honors them; " \
              "remove the MAIL_ON_RAILS_MTA_STS=0 override)"
          end
        end
        posture_warning do
          unless Settings[:dane]
            "recipient DANE/TLSA records are ignored on delivery - a downgrade to an " \
              "unauthenticated certificate goes unnoticed (the default honors them; remove " \
              "the MAIL_ON_RAILS_DANE=0 override)"
          end
        end
        posture_warning do
          unless Settings[:bimi]
            "BIMI logo display is off - inbound brand indicators are not fetched or shown " \
              "(the default is on; remove the MAIL_ON_RAILS_BIMI=0 override)"
          end
        end
        posture_warning do
          max_age = Settings[:mailroom_seal_max_age].to_i
          if max_age > SEAL_MAX_AGE_UNUSUAL
            "mailroom_seal_max_age is #{max_age}s (#{max_age / 86_400} days) - that is the replay " \
              "window for a captured sealed message; raise it only for the duration of a backlog " \
              "recovery, then return it toward the 6h default"
          end
        end
      end

      def posture_warning
        warning = yield
        @warnings << warning if warning
      rescue StandardError
        nil # an env error here is already reported by check_env
      end

      # Best-effort: only meaningful in a process with the database tier
      # wired (the standalone CLI boots the host app first).
      def check_db_rows
        return unless defined?(MailOnRails::Setting) && MailOnRails::Setting.table_exists?

        MailOnRails::Setting.override_rows.each do |key, raw|
          definition = Settings.lookup(key.to_s.to_sym)
          unless definition
            @warnings << "settings row #{key.inspect} matches no declared setting and is ignored"
            next
          end
          unless definition.dynamic?
            @warnings << "settings row #{key.inspect} is boot-only configuration and is ignored"
            next
          end
          begin
            definition.coerce(raw)
          rescue StandardError => e
            @warnings << "settings row #{key.inspect} is unusable and ignored: #{e.message}"
          end
        end
      rescue StandardError
        nil # no database in this process - nothing to check
      end
    end
  end
end
