# frozen_string_literal: true

require "ipaddr"
require "resolv"
require_relative "settings/definition"
require_relative "settings/dynamic_overrides"

module MailOnRails
  # The unified configuration surface: one declarative schema for every
  # tunable the mail servers and their Rails-side models read, layered as
  #
  #   gem default  <  ENV (legacy variable names)  <  initializer  <  DB
  #
  # The DB tier applies only to scope: :dynamic settings - the ones a
  # running listener can honor without a restart (toggles, limits,
  # timeouts, service addresses). scope: :static settings (ports, bind
  # addresses, TLS material, secrets) are fixed at boot from ENV or the
  # initializer; Setting.write refuses them, so the admin UI cannot create
  # dead rows.
  #
  # Reads:
  #   Settings[:smtp_max_conn]      # full precedence (the normal call)
  #   Settings.static(:smtp_port)   # boot tiers only (initializer/ENV/default)
  #
  # Host wiring:
  #   config.mail_on_rails.setting_overrides = { smtp_max_conn: 200 }  # initializer tier
  #   Settings.store = -> { Setting.override_rows }                    # DB tier (the engine does this)
  #
  # Stdlib-only and Zeitwerk-ignored like the rest of the protocol tree:
  # the servers read these on accept/session paths in processes that may
  # have no Rails at all, in which case the DB tier is simply absent and
  # reads resolve from ENV exactly as before the schema existed.
  module Settings
    @definitions = {}
    @overrides = {}
    @dynamic = DynamicOverrides.new

    class << self
      # Declares one setting. Used only by the schema below.
      def setting(name, **options)
        @definitions[name] = Definition.new(name: name, **options)
      end

      def definitions = @definitions.values
      def lookup(name) = @definitions[name]

      def definition(name)
        @definitions.fetch(name) { raise ArgumentError, "unknown setting #{name.inspect}" }
      end

      # The effective value: DB override first for dynamic settings, then
      # the boot tiers. The DB snapshot is a frozen in-memory hash (see
      # DynamicOverrides), so this is safe on accept paths.
      def [](name)
        defn = definition(name)
        if defn.dynamic?
          @dynamic.snapshot.fetch(name) { static_value(defn) }
        else
          static_value(defn)
        end
      end

      # The boot-tier value only (initializer, then ENV, then default) -
      # for consumers that must ignore DB overrides, like fallbacks that
      # run when the database is unreachable.
      def static(name)
        static_value(definition(name))
      end

      # Which tier supplies the effective value - the settings UI shows
      # this ("overridden here" vs "from ENV") and check reports it.
      def provenance(name)
        defn = definition(name)
        return :db if defn.dynamic? && @dynamic.snapshot.key?(name)
        return :initializer if @overrides.key?(name)
        return :env if defn.env && ENV.key?(defn.env)

        :default
      end

      # The initializer tier, validated eagerly so a typo fails the boot
      # with the setting's name rather than misbehaving quietly at runtime.
      def overrides=(hash)
        validated = {}
        (hash || {}).each do |name, value|
          validated[name.to_sym] = definition(name.to_sym).coerce(value)
        end
        @overrides = validated
      end

      # DB-tier source: a callable returning Hash[key => raw string], or
      # nil to detach. Wired by the engine; tests inject fakes.
      def store=(callable)
        @dynamic.store = callable
      end

      # Reloads the DB tier now, bypassing its poll interval - called from
      # Setting's after_commit so an admin's change applies immediately.
      def refresh!
        @dynamic.refresh!
      end

      # How long the DB snapshot is trusted between pulls. Test seam: app
      # suites run transactionally, where after_commit (the push half)
      # never fires - a 0 TTL makes every read see the current rows.
      def cache_ttl=(seconds)
        @dynamic.ttl = seconds
      end

      # Parses every declared ENV variable, raising Netserv::Config::Error
      # on the first bad one. The daemons call this at start so a typo
      # fails the boot (as the old load-time constants did) instead of
      # surfacing per connection.
      def validate_env!
        @definitions.each_value(&:env_value)
        true
      end

      # Test helper: back to pure defaults + ENV.
      def reset!
        @overrides = {}
        @dynamic = DynamicOverrides.new
      end

      private

      def static_value(definition)
        return @overrides[definition.name] if @overrides.key?(definition.name)

        definition.env_value
      end
    end

    # ------------------------------------------------------------------
    # Schema. ENV names are the historical ones - deployments configured
    # through the environment behave identically. Defaults are the
    # enforcing posture (verified outbound TLS, DMARC enforcement,
    # MTA-STS enforce, rspamd fail-closed): a fresh deploy is hardened
    # out of the box, and a deployment soaking toward that posture
    # weakens the relevant knob explicitly (Settings::Check keeps
    # reminding until the override is removed).
    # ------------------------------------------------------------------

    HELO_HOSTNAME_PATTERN = /\A(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\z/
    VALID_HOSTNAME = lambda do |value|
      if value.length > 255 || !value.match?(HELO_HOSTNAME_PATTERN)
        raise ArgumentError, "must be a hostname like mail.example.com"
      end
    end
    BLANK_TO_NIL = ->(value) { v = value.strip; v.empty? ? nil : v }

    # Scanner addresses are admin-tunable at runtime, so their shape is
    # bounded here: a settings-UI lever must not become an SSRF hop to
    # link-local/metadata space or an arbitrary URL. Loopback and private
    # hosts stay allowed - that is the normal deployment. Hostnames are
    # resolved and held to the same bar as literals: metadata.internal or
    # an attacker-controlled name pointing at 169.254.169.254 must fail
    # exactly like the literal would. A name that does not resolve passes
    # - accessories may be down (or their DNS absent) when a value is
    # written, and an unresolvable host cannot be scanned anyway; the
    # residual is a post-validation rebinding, which needs connect-time
    # pinning this admin-only gate does not attempt.
    SCANNER_HOST = lambda do |host|
      raise ArgumentError, "must include a host" if host.empty?

      begin
        addresses = [ IPAddr.new(host) ]
      rescue IPAddr::InvalidAddressError
        unless host.length <= 255 && host.downcase.match?(HELO_HOSTNAME_PATTERN)
          raise ArgumentError, "must be a hostname or IP address"
        end
        addresses = Resolv.getaddresses(host).filter_map do |address|
          IPAddr.new(address)
        rescue IPAddr::InvalidAddressError
          nil
        end
      end
      if addresses.any?(&:link_local?)
        raise ArgumentError, "must not point at link-local/metadata address space"
      end
    end
    SCANNER_PORT = lambda do |port|
      unless port.match?(/\A\d{1,5}\z/) && (1..65_535).cover?(port.to_i)
        raise ArgumentError, "port must be 1-65535"
      end
    end
    VALID_CLAMAV_ADDR = lambda do |value|
      next if value.nil? || value.empty?

      host, port = value.split(":", 2)
      SCANNER_HOST.call(host.to_s)
      SCANNER_PORT.call(port) if port
    end
    VALID_RSPAMD_ADDR = lambda do |value|
      next if value.nil? || value.empty?

      hostport = value
      if value.include?("://")
        scheme, _, rest = value.partition("://")
        unless %w[http https].include?(scheme.downcase)
          raise ArgumentError, "scheme must be http or https"
        end
        hostport = rest.split("/", 2).first.to_s
      end
      host, port = hostport.split(":", 2)
      SCANNER_HOST.call(host.to_s)
      SCANNER_PORT.call(port) if port
    end

    # -- SMTP limits ----------------------------------------------------
    setting :smtp_max_conn, type: :integer, default: 100, min: 1, env: "SMTP_MAX_CONN",
            scope: :dynamic, category: :smtp_limits,
            desc: "Process-wide concurrent SMTP connection cap"
    setting :smtp_max_conn_per_ip, type: :integer, default: 10, env: "SMTP_MAX_CONN_PER_IP",
            scope: :dynamic, category: :smtp_limits,
            desc: "Concurrent SMTP connections allowed per peer IP (0 disables)"
    setting :smtp_auth_lockout_failures, type: :integer, default: 10, env: "SMTP_AUTH_LOCKOUT_FAILURES",
            scope: :dynamic, category: :smtp_limits,
            desc: "Failed AUTHs before an IP is locked out (0 disables)"
    setting :smtp_auth_lockout_seconds, type: :integer, default: 900, min: 1, env: "SMTP_AUTH_LOCKOUT_SECONDS",
            scope: :dynamic, category: :smtp_limits,
            desc: "How long an SMTP auth lockout lasts"
    setting :smtp_conn_rate, type: :integer, default: 60, env: "SMTP_CONN_RATE",
            scope: :dynamic, category: :smtp_limits,
            desc: "SMTP connections per IP per window before tarpitting (0 disables)"
    setting :smtp_conn_rate_window, type: :integer, default: 60, min: 1, env: "SMTP_CONN_RATE_WINDOW",
            scope: :dynamic, category: :smtp_limits,
            desc: "Window for the SMTP connection rate, seconds"
    setting :smtp_send_quota, type: :integer, default: 200, env: "SMTP_SEND_QUOTA",
            scope: :dynamic, category: :smtp_limits,
            desc: "Recipients an authenticated account may send per window (0 disables)"
    setting :smtp_send_quota_window, type: :integer, default: 3600, min: 1, env: "SMTP_SEND_QUOTA_WINDOW",
            scope: :dynamic, category: :smtp_limits,
            desc: "Window for the send quota, seconds"
    setting :smtp_trace, type: :boolean, default: false, env: "SMTP_TRACE",
            scope: :dynamic, category: :smtp_limits,
            desc: "Log full SMTP protocol traces (new connections)"
    setting :smtp_trace_capture, type: :boolean, default: false, env: "SMTP_TRACE_CAPTURE",
            scope: :dynamic, category: :smtp_limits,
            desc: "Store per-session transcripts of abnormally ended SMTP connections for the /smtp page " \
                  "(new connections; command/reply dialogue only - no message bodies, credentials redacted)"
    setting :smtp_smtputf8, type: :boolean, default: true, env: "SMTP_SMTPUTF8",
            scope: :dynamic, category: :smtp_limits,
            desc: "Offer SMTPUTF8 (RFC 6531): accept internationalized (UTF-8) envelope addresses and " \
                  "relay them to next hops that advertise support; delivery to a hop without it bounces " \
                  "5.6.7 rather than downgrading (set 0 to refuse non-ASCII envelopes as before)"
    setting :smtp_session_seconds, type: :integer, default: 3600, env: "SMTP_SESSION_SECONDS",
            scope: :static, category: :smtp_limits,
            desc: "Absolute SMTP session lifetime, seconds (0 disables; boot-only)"

    # -- IMAP limits ----------------------------------------------------
    setting :imap_max_conn, type: :integer, default: 100, min: 1, env: "MAIL_ON_RAILS_IMAP_MAX_CONN",
            scope: :dynamic, category: :imap_limits,
            desc: "Process-wide concurrent IMAP connection cap"
    setting :imap_max_conn_per_ip, type: :integer, default: 10, env: "MAIL_ON_RAILS_IMAP_MAX_CONN_PER_IP",
            scope: :dynamic, category: :imap_limits,
            desc: "Concurrent IMAP connections allowed per peer IP (0 disables)"
    setting :imap_auth_lockout_failures, type: :integer, default: 10, env: "MAIL_ON_RAILS_IMAP_AUTH_LOCKOUT_FAILURES",
            scope: :dynamic, category: :imap_limits,
            desc: "Failed logins before an IP is locked out (0 disables)"
    setting :imap_auth_lockout_seconds, type: :integer, default: 900, min: 1, env: "MAIL_ON_RAILS_IMAP_AUTH_LOCKOUT_SECONDS",
            scope: :dynamic, category: :imap_limits,
            desc: "How long an IMAP auth lockout lasts"
    setting :imap_conn_rate, type: :integer, default: 60, env: "MAIL_ON_RAILS_IMAP_CONN_RATE",
            scope: :dynamic, category: :imap_limits,
            desc: "IMAP connections per IP per window before tarpitting (0 disables)"
    setting :imap_conn_rate_window, type: :integer, default: 60, min: 1, env: "MAIL_ON_RAILS_IMAP_CONN_RATE_WINDOW",
            scope: :dynamic, category: :imap_limits,
            desc: "Window for the IMAP connection rate, seconds"
    setting :imap_idle_poll, type: :integer, default: 30, min: 1, env: "MAIL_ON_RAILS_IMAP_IDLE_POLL",
            scope: :dynamic, category: :imap_limits,
            desc: "How often an idling IMAP session re-checks the store, seconds"
    setting :imap_trace, type: :boolean, default: false, env: "MAIL_ON_RAILS_IMAP_TRACE",
            scope: :dynamic, category: :imap_limits,
            desc: "Log full IMAP protocol traces (new connections)"
    setting :imap_trace_capture, type: :boolean, default: false, env: "MAIL_ON_RAILS_IMAP_TRACE_CAPTURE",
            scope: :dynamic, category: :imap_limits,
            desc: "Store per-session transcripts of abnormally ended IMAP connections for the /imap page " \
                  "(new connections; command/reply dialogue only - no literals, credentials redacted)"
    setting :imap_max_line, type: :integer, default: 65_536, min: 1024, env: "MAIL_ON_RAILS_IMAP_MAX_LINE",
            scope: :static, category: :imap_limits,
            desc: "Cap on a single IMAP command line, bytes (boot-only)"
    setting :imap_session_seconds, type: :integer, default: 86_400, env: "MAIL_ON_RAILS_IMAP_SESSION_SECONDS",
            scope: :static, category: :imap_limits,
            desc: "Absolute IMAP session lifetime, seconds (0 disables; default 24h - clients reconnect transparently, and a hijacked TCP session must not outlive the process; boot-only)"
    setting :imap_append_fail_closed, type: :boolean, default: true, env: "MAIL_ON_RAILS_IMAP_APPEND_FAIL_CLOSED",
            scope: :dynamic, category: :imap_limits,
            desc: "Refuse IMAP APPEND (and the web-UI import that mirrors it) when the virus scanner is unreachable, " \
                  "instead of storing the message flagged unscanned (default on, mirroring the SMTP edge's 451; " \
                  "set 0 to keep mail clients working through a scanner outage)"

    # -- Inbound filtering ---------------------------------------------
    setting :smtp_sender_auth, type: :boolean, default: true, env: "SMTP_SENDER_AUTH",
            scope: :dynamic, category: :filtering,
            desc: "Verify SPF/DKIM/DMARC on unauthenticated inbound mail"
    setting :smtp_dmarc_enforce, type: :boolean, default: true, env: "SMTP_DMARC_ENFORCE",
            scope: :dynamic, category: :filtering,
            desc: "Reject at SMTP time when DMARC p=reject fails (default on; set 0 to log-only while soaking)"
    setting :smtp_sender_auth_fail_closed, type: :boolean, default: true, env: "SMTP_SENDER_AUTH_FAIL_CLOSED",
            scope: :dynamic, category: :filtering,
            desc: "Tempfail (451) unauthenticated inbound mail when DMARC evaluation hits a transient DNS error " \
                  "while enforcement is on, instead of accepting with a temperror stamp - a DNS outage must not " \
                  "become a spoofing window (default on; set 0 to accept-and-stamp through DNS outages)"
    setting :smtp_arc_trusted_sealers, type: :list, default: [], env: "SMTP_ARC_TRUSTED_SEALERS",
            scope: :dynamic, category: :filtering,
            desc: "ARC sealer domains (RFC 8617) whose intact arc=pass chain overrides a DMARC p=reject " \
                  "verdict - the mailing-list/forwarder allowlist; empty disables the override"
    setting :smtp_rbl_zones, type: :list, default: [], env: "SMTP_RBLS",
            scope: :dynamic, category: :filtering,
            desc: "DNSBL zones checked for unauthenticated senders (empty disables)"
    setting :smtp_rbl_cache_ttl, type: :integer, default: 600, min: 1, env: "SMTP_RBL_CACHE_TTL",
            scope: :dynamic, category: :filtering,
            desc: "DNSBL verdict cache lifetime, seconds"
    setting :smtp_clamav_addr, type: :addr, default: "", env: "SMTP_CLAMAV_ADDR",
            scope: :dynamic, category: :filtering, validate: VALID_CLAMAV_ADDR,
            desc: "clamd address (host:port) for virus scanning (empty disables)"
    setting :smtp_clamav_timeout, type: :integer, default: 10, min: 1, env: "SMTP_CLAMAV_TIMEOUT",
            scope: :dynamic, category: :filtering,
            desc: "clamd scan timeout, seconds"
    setting :smtp_clamav_optional, type: :boolean, default: false, env: "SMTP_CLAMAV_OPTIONAL",
            scope: :static, category: :filtering,
            desc: "Allow the mail servers to boot in production with no clamd address - an explicit opt-out of " \
                  "virus scanning; without it an empty SMTP_CLAMAV_ADDR fails the production boot (boot-only)"
    setting :smtp_rspamd_addr, type: :addr, default: "", env: "SMTP_RSPAMD_ADDR",
            scope: :dynamic, category: :filtering, validate: VALID_RSPAMD_ADDR,
            desc: "rspamd worker address (host:port) for spam analysis (empty disables)"
    setting :smtp_rspamd_timeout, type: :integer, default: 10, min: 1, env: "SMTP_RSPAMD_TIMEOUT",
            scope: :dynamic, category: :filtering,
            desc: "rspamd HTTP timeout, seconds"
    setting :smtp_rspamd_password, type: :string, default: "", env: "SMTP_RSPAMD_PASSWORD",
            scope: :static, category: :filtering, secret: true,
            desc: "rspamd controller password (boot-only)"
    setting :smtp_rspamd_fail_closed, type: :boolean, default: true, env: "SMTP_RSPAMD_FAIL_CLOSED",
            scope: :dynamic, category: :filtering,
            desc: "Reject authenticated submission when rspamd is unreachable, instead of accepting unscored (inbound always fails open; default on, set 0 to fail open)"
    setting :smtp_from_alignment, type: :boolean, default: true, env: "SMTP_FROM_ALIGNMENT",
            scope: :dynamic, category: :filtering,
            desc: "Require authenticated submissions' visible From: (and Sender:, if present) to be the " \
                  "authenticated account or one of its aliases, and require a From header at all - RFC 6409 " \
                  "MSA authorization; failures are refused 550 (set 0 to accept arbitrary From headers as before)"
    setting :smtp_rspamd_greylist, type: :boolean, default: true, env: "SMTP_RSPAMD_GREYLIST",
            scope: :dynamic, category: :filtering,
            desc: "Honor rspamd's greylist verdict with a 451 deferral at submission time, instead of accepting " \
                  "(a conformant client retries and passes once rspamd's greylist window elapses; set 0 to accept)"
    setting :smtp_fcrdns, type: :boolean, default: true, env: "SMTP_FCRDNS",
            scope: :dynamic, category: :filtering,
            desc: "Resolve the connecting client's PTR and forward-confirm it (FCrDNS), and check the HELO name " \
                  "resolves to the peer - recorded in the Received header and logged, never a rejection by itself"
    setting :smtp_dmarc_reports, type: :boolean, default: true, env: "SMTP_DMARC_REPORTS",
            scope: :dynamic, category: :filtering,
            desc: "Record per-message DMARC evaluations and send daily RFC 7489 aggregate reports to the rua= " \
                  "addresses of domains whose mail this server receives (SendDmarcReportsJob)"
    setting :bimi, type: :boolean, default: true, env: "MAIL_ON_RAILS_BIMI",
            scope: :dynamic, category: :filtering,
            desc: "Look up and display BIMI brand logos (self-asserted accepted) for inbound senders whose " \
                  "mail passed DMARC under an enforcing policy; logos are fetched once per domain per day, " \
                  "strictly sanitized, and cached (BimiIndicator)"
    setting :mailroom_dmarc_enforce, type: :string, default: "enforce", env: "MAILROOM_DMARC_ENFORCE",
            scope: :dynamic, category: :filtering,
            validate: lambda { |value|
              unless %w[log enforce off 0 1].include?(value)
                raise ArgumentError, "must be one of log/enforce/off"
              end
            },
            desc: "File DMARC p=reject failures into Junk: log, enforce, or off"
    setting :mailroom_require_seal, type: :boolean, default: true, env: "MAILROOM_REQUIRE_SEAL",
            scope: :dynamic, category: :filtering,
            desc: "Drop inbound email whose trusted routing/auth headers lack a valid internal seal"
    setting :mailroom_seal_max_age, type: :integer, default: 21_600, min: 60, env: "MAILROOM_SEAL_MAX_AGE",
            scope: :dynamic, category: :filtering,
            desc: "How long an ingress seal stays valid, seconds - the replay window for a captured sealed " \
                  "message, and the routing-job backlog the mailroom will still accept (default 6h; raise it " \
                  "during backlog recovery instead of disabling MAILROOM_REQUIRE_SEAL)"

    # -- Outbound delivery ---------------------------------------------
    setting :outbound_limit, type: :integer, default: 1000, min: 1, env: "MAIL_ON_RAILS_OUTBOUND_LIMIT",
            scope: :dynamic, category: :outbound,
            desc: "Cap on the outbound QUEUE DEPTH: a submission that would push pending deliveries past " \
                  "this is refused 452 (insufficient storage). Drain speed is a separate, deliberately " \
                  "fixed pace: 50 rows per 15-second run, further paced per destination domain by " \
                  "smtp_outbound_domain_batch"
    setting :smtp_outbound_domain_batch, type: :integer, default: 10, min: 0,
            env: "SMTP_OUTBOUND_DOMAIN_BATCH", scope: :dynamic, category: :outbound,
            desc: "Deliveries attempted per destination domain per queue run - large ISPs rate-limit by source " \
                  "IP, so a burst to one domain is paced across runs instead of hammered at once; a transient " \
                  "failure also skips the domain's remaining messages for that run (0 disables both)"
    setting :smtp_list_unsubscribe, type: :boolean, default: true,
            env: "SMTP_LIST_UNSUBSCRIBE", scope: :dynamic, category: :outbound,
            desc: "Inject List-Unsubscribe and RFC 8058 one-click List-Unsubscribe-Post headers into outbound " \
                  "list mail (messages carrying a List-ID header) from hosted domains, before DKIM signing - " \
                  "the Gmail/Yahoo bulk-sender mandate (0 disables)"
    setting :smtp_verp, type: :boolean, default: true, env: "SMTP_VERP",
            scope: :dynamic, category: :outbound,
            desc: "VERP for outbound list mail (messages carrying List-ID from a hosted domain): the envelope " \
                  "sender becomes a signed per-message bounce+ address at the sender's domain, so asynchronous " \
                  "bounces attribute themselves - hard (5.x.x) DSNs coming back suppress that sender's future " \
                  "mail to the dead address (IngestBounceJob). Personal mail keeps its normal return path"
    setting :dkim_rotation_days, type: :integer, default: 0, min: 0, env: "MAIL_ON_RAILS_DKIM_ROTATION_DAYS",
            scope: :dynamic, category: :outbound,
            desc: "Rotate each hosted domain's DKIM key automatically once its selector is this many days old " \
                  "(RotateDkimKeysJob: stage new key, publish via Cloudflare, promote once DNS shows it, revoke " \
                  "the old selector after a grace week). 0 (default) leaves rotation manual - stage from the " \
                  "domain page; the job still promotes staged keys and revokes retired ones"
    setting :smtp_dkim_required, type: :boolean, default: true, env: "SMTP_DKIM_REQUIRED",
            scope: :dynamic, category: :outbound,
            desc: "Defer outbound mail from a hosted domain when DKIM signing fails, instead of sending it " \
                  "unsigned (default on - the queue retries with backoff and bounces on exhaustion; domains " \
                  "with no Domain record are never held to this; set 0 to send unsigned on signing failure)"
    setting :smtp_delay_warning_seconds, type: :integer, default: 14_400, min: 0,
            env: "SMTP_DELAY_WARNING_SECONDS", scope: :dynamic, category: :outbound,
            desc: "Send the author a delayed-delivery DSN once an outbound message has been queued this " \
                  "long, seconds (once per message; 0 disables; default 4h)"
    setting :mta_sts, type: :boolean, default: true, env: "MAIL_ON_RAILS_MTA_STS",
            scope: :dynamic, category: :outbound,
            desc: "Honor recipient MTA-STS policies when delivering"
    setting :dane, type: :boolean, default: true, env: "MAIL_ON_RAILS_DANE",
            scope: :dynamic, category: :outbound,
            desc: "Honor recipient DANE/TLSA records when delivering"
    setting :mta_sts_max_age, type: :integer, default: nil, min: 3600, max: 31_557_600,
            env: "MAIL_ON_RAILS_MTA_STS_MAX_AGE", scope: :dynamic, category: :outbound,
            desc: "Published MTA-STS policy max_age, seconds (blank: mode-based default)"
    setting :mta_sts_mode, type: :string, default: "enforce", env: "MAIL_ON_RAILS_MTA_STS_MODE",
            scope: :static, category: :outbound,
            validate: lambda { |value|
              unless %w[testing enforce none].include?(value)
                raise ArgumentError, "must be one of testing/enforce/none"
              end
            },
            desc: "Published MTA-STS policy mode (boot-only)"
    setting :dkim_selector, type: :string, default: "rail", env: "MAIL_ON_RAILS_DKIM_SELECTOR",
            scope: :static, category: :outbound,
            desc: "DKIM selector for signing and published DNS (boot-only)"
    setting :smarthost, type: :addr, default: nil, env: "MAIL_ON_RAILS_SMARTHOST",
            scope: :static, category: :outbound,
            desc: "Relay all outbound mail through host[:port] instead of direct MX (boot-only)"
    setting :smarthost_user, type: :string, default: nil, env: "MAIL_ON_RAILS_SMARTHOST_USER",
            scope: :static, category: :outbound, secret: true,
            desc: "Smarthost AUTH user (boot-only)"
    setting :smarthost_password, type: :string, default: nil, env: "MAIL_ON_RAILS_SMARTHOST_PASSWORD",
            scope: :static, category: :outbound, secret: true,
            desc: "Smarthost AUTH password (boot-only)"
    setting :smarthost_tls, type: :string, default: "opportunistic", env: "MAIL_ON_RAILS_SMARTHOST_TLS",
            scope: :static, category: :outbound,
            validate: lambda { |value|
              unless %w[opportunistic starttls smtps].include?(value)
                raise ArgumentError, "must be one of opportunistic/starttls/smtps"
              end
            },
            desc: "Smarthost transport security: opportunistic, starttls (required+verified), or smtps (boot-only)"
    setting :smtp_outbound_require_verified_tls, type: :boolean, default: true, env: "SMTP_OUTBOUND_REQUIRE_VERIFIED_TLS",
            scope: :dynamic, category: :outbound,
            desc: "Require verified STARTTLS for all direct outbound delivery, not just DANE/MTA-STS hosts (default on; set 0 for opportunistic delivery while TLS-RPT soaks)"
    setting :dns_nameservers, type: :list, default: [], env: "MAIL_ON_RAILS_DNS_NAMESERVERS",
            scope: :static, category: :outbound,
            desc: "Nameservers the mail DNS client queries instead of /etc/resolv.conf. DNSSEC for DANE " \
                  "is validated in-process against the IANA root trust anchor, so no nameserver needs to " \
                  "be trusted - Docker's embedded stub works fine (boot-only)"
    setting :dns_fallback_nameservers, type: :list, default: [ "8.8.8.8", "1.1.1.1" ],
            env: "MAIL_ON_RAILS_DNS_FALLBACK_NAMESERVERS",
            scope: :static, category: :outbound,
            desc: "Public resolvers tried for DNSSEC queries only after every dns_nameservers upstream " \
                  "fails - some local stubs cannot serve large answers like the root DNSKEY RRset. " \
                  "Validation stays in-process, so these need no trust; set empty to never query " \
                  "third parties (boot-only)"

    # -- Cross-protocol auth brute-force analysis ----------------------
    setting :auth_window, type: :integer, default: 900, min: 1, env: "MAIL_ON_RAILS_AUTH_WINDOW",
            scope: :dynamic, category: :auth_bruteforce,
            desc: "Failure-counting window for the auth throttle, seconds"
    setting :auth_max_ip_failures, type: :integer, default: 20, min: 1, env: "MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES",
            scope: :dynamic, category: :auth_bruteforce,
            desc: "Failures per IP within the window before blocking"
    setting :auth_max_account_failures, type: :integer, default: 10, min: 1, env: "MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES",
            scope: :dynamic, category: :auth_bruteforce,
            desc: "Failures per account within the window before blocking"
    setting :auth_ip_block, type: :integer, default: 900, min: 1, env: "MAIL_ON_RAILS_AUTH_IP_BLOCK",
            scope: :dynamic, category: :auth_bruteforce,
            desc: "IP block duration, seconds"
    setting :auth_account_block, type: :integer, default: 300, min: 1, env: "MAIL_ON_RAILS_AUTH_ACCOUNT_BLOCK",
            scope: :dynamic, category: :auth_bruteforce,
            desc: "Account block duration, seconds"

    # -- Log retention --------------------------------------------------
    setting :trash_retention_days, type: :integer, default: 30, min: 1,
            scope: :dynamic, category: :retention,
            desc: "Days a message sits in Trash before permanent deletion"
    setting :conn_log_retention_days, type: :integer, default: 90, env: "MAIL_ON_RAILS_CONN_LOG_RETENTION_DAYS",
            scope: :dynamic, category: :retention,
            desc: "Days closed-connection history is kept"
    setting :conn_log_max_rows_per_ip, type: :integer, default: 50, env: "MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP",
            scope: :dynamic, category: :retention,
            desc: "Closed-connection rows kept per IP before rollup"
    setting :conn_log_rollup_window, type: :integer, default: 3600, min: 1, env: "MAIL_ON_RAILS_CONN_LOG_ROLLUP_WINDOW",
            scope: :dynamic, category: :retention,
            desc: "Rollup window for connection-log pruning, seconds"
    setting :transcript_retention_days, type: :integer, default: 7, min: 1, env: "MAIL_ON_RAILS_TRANSCRIPT_RETENTION_DAYS",
            scope: :dynamic, category: :retention,
            desc: "Days captured session transcripts (smtp/imap_trace_capture) are kept"
    setting :auth_log_retention_days, type: :integer, default: 30, env: "MAIL_ON_RAILS_AUTH_LOG_RETENTION_DAYS",
            scope: :dynamic, category: :retention,
            desc: "Days auth-attempt history is kept"
    setting :auth_log_max_rows_per_ip, type: :integer, default: 50, env: "MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP",
            scope: :dynamic, category: :retention,
            desc: "Auth-attempt rows kept per IP before rollup"
    setting :auth_log_rollup_window, type: :integer, default: 3600, min: 1, env: "MAIL_ON_RAILS_AUTH_LOG_ROLLUP_WINDOW",
            scope: :dynamic, category: :retention,
            desc: "Rollup window for auth-log pruning, seconds"

    # -- Honeypot -------------------------------------------------------
    setting :honeypot_retention_days, type: :integer, default: 365, env: "MAIL_ON_RAILS_HONEYPOT_RETENTION_DAYS",
            scope: :dynamic, category: :honeypot,
            desc: "Days honeypot events are kept"
    setting :honeypot_block_seconds, type: :integer, default: 3600, env: "MAIL_ON_RAILS_HONEYPOT_BLOCK_SECONDS",
            scope: :dynamic, category: :honeypot,
            desc: "Auto-ban duration for a triggered honeypot, seconds"
    setting :honeypot_collateral_days, type: :integer, default: 7, env: "MAIL_ON_RAILS_HONEYPOT_COLLATERAL_DAYS",
            scope: :dynamic, category: :honeypot,
            desc: "Lookback for legitimate traffic before auto-banning a shared IP, days"
    setting :honeypot_allowlist, type: :list, default: [], env: "MAIL_ON_RAILS_HONEYPOT_ALLOWLIST",
            scope: :dynamic, category: :honeypot,
            desc: "CIDRs never auto-banned by the honeypot"
    setting :honeypot_banner, type: :string, default: nil, env: "MAIL_ON_RAILS_HONEYPOT_BANNER",
            scope: :static, category: :honeypot, normalize: BLANK_TO_NIL,
            desc: "Deceptive product banner in SMTP/IMAP greetings (boot-only; blank: real banner)"

    # -- Identity -------------------------------------------------------
    setting :smtp_helo_hostname, type: :string, default: nil, env: "SMTP_HELO_HOST",
            scope: :dynamic, category: :identity,
            normalize: ->(value) { v = value.strip.downcase; v.empty? ? nil : v },
            validate: VALID_HOSTNAME,
            desc: "Hostname announced in SMTP banners and outbound HELO"
    setting :smtp_vrfy_response, type: :string, default: "252", env: "SMTP_VRFY_RESPONSE",
            scope: :dynamic, category: :identity,
            validate: lambda { |value|
              unless %w[252 502].include?(value)
                raise ArgumentError, "must be 252 or 502"
              end
            },
            desc: "Reply to the VRFY command: 252 (cannot verify, accepts anyway) or 502 (refused as not implemented)"
    setting :dns_check_nameservers, type: :list, default: %w[1.1.1.1 8.8.8.8],
            env: "MAIL_ON_RAILS_DNS_CHECK_NAMESERVERS",
            scope: :dynamic, category: :identity,
            desc: "Resolvers used for domain DNS verification"

    # -- Network / TLS (boot-only) -------------------------------------
    setting :smtp_host, type: :string, default: "0.0.0.0", env: "SMTP_HOST",
            scope: :static, category: :network,
            desc: "SMTP bind address (\"::\" listens dual-stack, IPv6 and IPv4)"
    setting :smtp_port, type: :integer, default: 1025, min: 1, max: 65_535, env: "SMTP_PORT",
            scope: :static, category: :network, desc: "SMTP MX listener port (STARTTLS)"
    setting :smtp_submission_port, type: :integer, default: 1587, min: 1, max: 65_535, env: "SMTP_SUBMISSION_PORT",
            scope: :static, category: :network, desc: "SMTP submission port (STARTTLS)"
    setting :smtps_port, type: :integer, default: 1465, min: 1, max: 65_535, env: "SMTPS_PORT",
            scope: :static, category: :network, desc: "SMTP submission port (implicit TLS)"
    setting :imap_host, type: :string, default: "0.0.0.0", env: "MAIL_ON_RAILS_HOST",
            scope: :static, category: :network,
            desc: "IMAP bind address (\"::\" listens dual-stack, IPv6 and IPv4)"
    setting :imap_port, type: :integer, default: 1143, min: 1, max: 65_535, env: "MAIL_ON_RAILS_IMAP_PORT",
            scope: :static, category: :network, desc: "IMAP listener port (STARTTLS)"
    setting :imaps_port, type: :integer, default: 1993, min: 1, max: 65_535, env: "MAIL_ON_RAILS_IMAPS_PORT",
            scope: :static, category: :network, desc: "IMAP listener port (implicit TLS)"
    setting :smtp_tls_cert, type: :string, default: nil, env: "SMTP_TLS_CERT",
            scope: :static, category: :tls, desc: "SMTP TLS certificate path (PEM)"
    setting :smtp_tls_key, type: :string, default: nil, env: "SMTP_TLS_KEY",
            scope: :static, category: :tls, desc: "SMTP TLS private key path (PEM)"
    setting :smtp_tls_dir, type: :string, default: "storage/tls", env: "SMTP_TLS_DIR",
            scope: :static, category: :tls, desc: "Directory for the self-signed development cert (SMTP)"
    setting :smtp_tls_hosts, type: :list, default: %w[localhost], env: "SMTP_TLS_HOSTS",
            scope: :static, category: :tls, desc: "SANs on the self-signed development cert (SMTP)"
    setting :imap_tls_cert, type: :string, default: nil, env: "MAIL_ON_RAILS_TLS_CERT",
            scope: :static, category: :tls, desc: "IMAP TLS certificate path (PEM)"
    setting :imap_tls_key, type: :string, default: nil, env: "MAIL_ON_RAILS_TLS_KEY",
            scope: :static, category: :tls, desc: "IMAP TLS private key path (PEM)"
    setting :imap_tls_dir, type: :string, default: "storage/tls", env: "MAIL_ON_RAILS_TLS_DIR",
            scope: :static, category: :tls, desc: "Directory for the self-signed development cert (IMAP)"
    setting :imap_tls_hosts, type: :list, default: %w[localhost], env: "MAIL_ON_RAILS_TLS_HOSTS",
            scope: :static, category: :tls, desc: "SANs on the self-signed development cert (IMAP)"
  end
end
