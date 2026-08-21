# Configuration reference

Generated from the settings schema (`lib/mail_on_rails/settings.rb`).
Precedence: gem default < environment variable < initializer override < settings table (dynamic only).

- **dynamic** settings accept database overrides from the admin Settings page and apply to running servers without a restart.
- **static** settings are read at boot from ENV or `config.mail_on_rails.setting_overrides`.

## smtp_limits

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `smtp_max_conn` | integer | 100 | `SMTP_MAX_CONN` | dynamic | Process-wide concurrent SMTP connection cap |
| `smtp_max_conn_per_ip` | integer | 10 | `SMTP_MAX_CONN_PER_IP` | dynamic | Concurrent SMTP connections allowed per peer IP (0 disables) |
| `smtp_auth_lockout_failures` | integer | 10 | `SMTP_AUTH_LOCKOUT_FAILURES` | dynamic | Failed AUTHs before an IP is locked out (0 disables) |
| `smtp_auth_lockout_seconds` | integer | 900 | `SMTP_AUTH_LOCKOUT_SECONDS` | dynamic | How long an SMTP auth lockout lasts |
| `smtp_conn_rate` | integer | 60 | `SMTP_CONN_RATE` | dynamic | SMTP connections per IP per window before tarpitting (0 disables) |
| `smtp_conn_rate_window` | integer | 60 | `SMTP_CONN_RATE_WINDOW` | dynamic | Window for the SMTP connection rate, seconds |
| `smtp_send_quota` | integer | 200 | `SMTP_SEND_QUOTA` | dynamic | Recipients an authenticated account may send per window (0 disables) |
| `smtp_send_quota_window` | integer | 3600 | `SMTP_SEND_QUOTA_WINDOW` | dynamic | Window for the send quota, seconds |
| `smtp_trace` | boolean | false | `SMTP_TRACE` | dynamic | Log full SMTP protocol traces (new connections) |
| `smtp_session_seconds` | integer | 3600 | `SMTP_SESSION_SECONDS` | static | Absolute SMTP session lifetime, seconds (0 disables; boot-only) |

## imap_limits

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `imap_max_conn` | integer | 100 | `MAIL_ON_RAILS_IMAP_MAX_CONN` | dynamic | Process-wide concurrent IMAP connection cap |
| `imap_max_conn_per_ip` | integer | 10 | `MAIL_ON_RAILS_IMAP_MAX_CONN_PER_IP` | dynamic | Concurrent IMAP connections allowed per peer IP (0 disables) |
| `imap_auth_lockout_failures` | integer | 10 | `MAIL_ON_RAILS_IMAP_AUTH_LOCKOUT_FAILURES` | dynamic | Failed logins before an IP is locked out (0 disables) |
| `imap_auth_lockout_seconds` | integer | 900 | `MAIL_ON_RAILS_IMAP_AUTH_LOCKOUT_SECONDS` | dynamic | How long an IMAP auth lockout lasts |
| `imap_conn_rate` | integer | 60 | `MAIL_ON_RAILS_IMAP_CONN_RATE` | dynamic | IMAP connections per IP per window before tarpitting (0 disables) |
| `imap_conn_rate_window` | integer | 60 | `MAIL_ON_RAILS_IMAP_CONN_RATE_WINDOW` | dynamic | Window for the IMAP connection rate, seconds |
| `imap_idle_poll` | integer | 30 | `MAIL_ON_RAILS_IMAP_IDLE_POLL` | dynamic | How often an idling IMAP session re-checks the store, seconds |
| `imap_trace` | boolean | false | `MAIL_ON_RAILS_IMAP_TRACE` | dynamic | Log full IMAP protocol traces (new connections) |
| `imap_max_line` | integer | 65536 | `MAIL_ON_RAILS_IMAP_MAX_LINE` | static | Cap on a single IMAP command line, bytes (boot-only) |
| `imap_session_seconds` | integer | 86400 | `MAIL_ON_RAILS_IMAP_SESSION_SECONDS` | static | Absolute IMAP session lifetime, seconds (0 disables; default 24h - clients reconnect transparently, and a hijacked TCP session must not outlive the process; boot-only) |
| `imap_append_fail_closed` | boolean | true | `MAIL_ON_RAILS_IMAP_APPEND_FAIL_CLOSED` | dynamic | Refuse IMAP APPEND (and the web-UI import that mirrors it) when the virus scanner is unreachable, instead of storing the message flagged unscanned (default on, mirroring the SMTP edge's 451; set 0 to keep mail clients working through a scanner outage) |

## filtering

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `smtp_sender_auth` | boolean | true | `SMTP_SENDER_AUTH` | dynamic | Verify SPF/DKIM/DMARC on unauthenticated inbound mail |
| `smtp_dmarc_enforce` | boolean | true | `SMTP_DMARC_ENFORCE` | dynamic | Reject at SMTP time when DMARC p=reject fails (default on; set 0 to log-only while soaking) |
| `smtp_sender_auth_fail_closed` | boolean | true | `SMTP_SENDER_AUTH_FAIL_CLOSED` | dynamic | Tempfail (451) unauthenticated inbound mail when DMARC evaluation hits a transient DNS error while enforcement is on, instead of accepting with a temperror stamp - a DNS outage must not become a spoofing window (default on; set 0 to accept-and-stamp through DNS outages) |
| `smtp_rbl_zones` | list | (empty) | `SMTP_RBLS` | dynamic | DNSBL zones checked for unauthenticated senders (empty disables) |
| `smtp_rbl_cache_ttl` | integer | 600 | `SMTP_RBL_CACHE_TTL` | dynamic | DNSBL verdict cache lifetime, seconds |
| `smtp_clamav_addr` | addr |  | `SMTP_CLAMAV_ADDR` | dynamic | clamd address (host:port) for virus scanning (empty disables) |
| `smtp_clamav_timeout` | integer | 10 | `SMTP_CLAMAV_TIMEOUT` | dynamic | clamd scan timeout, seconds |
| `smtp_clamav_optional` | boolean | false | `SMTP_CLAMAV_OPTIONAL` | static | Allow the mail servers to boot in production with no clamd address - an explicit opt-out of virus scanning; without it an empty SMTP_CLAMAV_ADDR fails the production boot (boot-only) |
| `smtp_rspamd_addr` | addr |  | `SMTP_RSPAMD_ADDR` | dynamic | rspamd worker address (host:port) for spam analysis (empty disables) |
| `smtp_rspamd_timeout` | integer | 10 | `SMTP_RSPAMD_TIMEOUT` | dynamic | rspamd HTTP timeout, seconds |
| `smtp_rspamd_password` | string |  | `SMTP_RSPAMD_PASSWORD` | static | rspamd controller password (boot-only) |
| `smtp_rspamd_fail_closed` | boolean | true | `SMTP_RSPAMD_FAIL_CLOSED` | dynamic | Reject authenticated submission when rspamd is unreachable, instead of accepting unscored (inbound always fails open; default on, set 0 to fail open) |
| `mailroom_dmarc_enforce` | string | enforce | `MAILROOM_DMARC_ENFORCE` | dynamic | File DMARC p=reject failures into Junk: log, enforce, or off |
| `mailroom_require_seal` | boolean | true | `MAILROOM_REQUIRE_SEAL` | dynamic | Drop inbound email whose trusted routing/auth headers lack a valid internal seal |
| `mailroom_seal_max_age` | integer | 21600 | `MAILROOM_SEAL_MAX_AGE` | dynamic | How long an ingress seal stays valid, seconds - the replay window for a captured sealed message, and the routing-job backlog the mailroom will still accept (default 6h; raise it during backlog recovery instead of disabling MAILROOM_REQUIRE_SEAL) |

## outbound

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `outbound_limit` | integer | 1000 | `MAIL_ON_RAILS_OUTBOUND_LIMIT` | dynamic | Outbound deliveries drained per queue run |
| `smtp_dkim_required` | boolean | true | `SMTP_DKIM_REQUIRED` | dynamic | Defer outbound mail from a hosted domain when DKIM signing fails, instead of sending it unsigned (default on - the queue retries with backoff and bounces on exhaustion; domains with no Domain record are never held to this; set 0 to send unsigned on signing failure) |
| `mta_sts` | boolean | true | `MAIL_ON_RAILS_MTA_STS` | dynamic | Honor recipient MTA-STS policies when delivering |
| `dane` | boolean | true | `MAIL_ON_RAILS_DANE` | dynamic | Honor recipient DANE/TLSA records when delivering |
| `mta_sts_max_age` | integer | (none) | `MAIL_ON_RAILS_MTA_STS_MAX_AGE` | dynamic | Published MTA-STS policy max_age, seconds (blank: mode-based default) |
| `mta_sts_mode` | string | enforce | `MAIL_ON_RAILS_MTA_STS_MODE` | static | Published MTA-STS policy mode (boot-only) |
| `dkim_selector` | string | rail | `MAIL_ON_RAILS_DKIM_SELECTOR` | static | DKIM selector for signing and published DNS (boot-only) |
| `smarthost` | addr | (none) | `MAIL_ON_RAILS_SMARTHOST` | static | Relay all outbound mail through host[:port] instead of direct MX (boot-only) |
| `smarthost_user` | string | (none) | `MAIL_ON_RAILS_SMARTHOST_USER` | static | Smarthost AUTH user (boot-only) |
| `smarthost_password` | string | (none) | `MAIL_ON_RAILS_SMARTHOST_PASSWORD` | static | Smarthost AUTH password (boot-only) |
| `smarthost_tls` | string | opportunistic | `MAIL_ON_RAILS_SMARTHOST_TLS` | static | Smarthost transport security: opportunistic, starttls (required+verified), or smtps (boot-only) |
| `smtp_outbound_require_verified_tls` | boolean | true | `SMTP_OUTBOUND_REQUIRE_VERIFIED_TLS` | dynamic | Require verified STARTTLS for all direct outbound delivery, not just DANE/MTA-STS hosts (default on; set 0 for opportunistic delivery while TLS-RPT soaks) |
| `dns_nameservers` | list | (empty) | `MAIL_ON_RAILS_DNS_NAMESERVERS` | static | Nameservers the mail DNS client queries instead of /etc/resolv.conf. DNSSEC for DANE is validated in-process against the IANA root trust anchor, so no nameserver needs to be trusted - Docker's embedded stub works fine (boot-only) |
| `dns_fallback_nameservers` | list | 8.8.8.8, 1.1.1.1 | `MAIL_ON_RAILS_DNS_FALLBACK_NAMESERVERS` | static | Public resolvers tried for DNSSEC queries only after every dns_nameservers upstream fails - some local stubs cannot serve large answers like the root DNSKEY RRset. Validation stays in-process, so these need no trust; set empty to never query third parties (boot-only) |

## auth_bruteforce

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `auth_window` | integer | 900 | `MAIL_ON_RAILS_AUTH_WINDOW` | dynamic | Failure-counting window for the auth throttle, seconds |
| `auth_max_ip_failures` | integer | 20 | `MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES` | dynamic | Failures per IP within the window before blocking |
| `auth_max_account_failures` | integer | 10 | `MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES` | dynamic | Failures per account within the window before blocking |
| `auth_ip_block` | integer | 900 | `MAIL_ON_RAILS_AUTH_IP_BLOCK` | dynamic | IP block duration, seconds |
| `auth_account_block` | integer | 300 | `MAIL_ON_RAILS_AUTH_ACCOUNT_BLOCK` | dynamic | Account block duration, seconds |

## retention

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `trash_retention_days` | integer | 30 | - | dynamic | Days a message sits in Trash before permanent deletion |
| `conn_log_retention_days` | integer | 90 | `MAIL_ON_RAILS_CONN_LOG_RETENTION_DAYS` | dynamic | Days closed-connection history is kept |
| `conn_log_max_rows_per_ip` | integer | 50 | `MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP` | dynamic | Closed-connection rows kept per IP before rollup |
| `conn_log_rollup_window` | integer | 3600 | `MAIL_ON_RAILS_CONN_LOG_ROLLUP_WINDOW` | dynamic | Rollup window for connection-log pruning, seconds |
| `auth_log_retention_days` | integer | 30 | `MAIL_ON_RAILS_AUTH_LOG_RETENTION_DAYS` | dynamic | Days auth-attempt history is kept |
| `auth_log_max_rows_per_ip` | integer | 50 | `MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP` | dynamic | Auth-attempt rows kept per IP before rollup |
| `auth_log_rollup_window` | integer | 3600 | `MAIL_ON_RAILS_AUTH_LOG_ROLLUP_WINDOW` | dynamic | Rollup window for auth-log pruning, seconds |

## honeypot

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `honeypot_retention_days` | integer | 365 | `MAIL_ON_RAILS_HONEYPOT_RETENTION_DAYS` | dynamic | Days honeypot events are kept |
| `honeypot_block_seconds` | integer | 3600 | `MAIL_ON_RAILS_HONEYPOT_BLOCK_SECONDS` | dynamic | Auto-ban duration for a triggered honeypot, seconds |
| `honeypot_collateral_days` | integer | 7 | `MAIL_ON_RAILS_HONEYPOT_COLLATERAL_DAYS` | dynamic | Lookback for legitimate traffic before auto-banning a shared IP, days |
| `honeypot_allowlist` | list | (empty) | `MAIL_ON_RAILS_HONEYPOT_ALLOWLIST` | dynamic | CIDRs never auto-banned by the honeypot |
| `honeypot_banner` | string | (none) | `MAIL_ON_RAILS_HONEYPOT_BANNER` | static | Deceptive product banner in SMTP/IMAP greetings (boot-only; blank: real banner) |

## identity

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `smtp_helo_hostname` | string | (none) | `SMTP_HELO_HOST` | dynamic | Hostname announced in SMTP banners and outbound HELO |
| `smtp_vrfy_response` | string | 252 | `SMTP_VRFY_RESPONSE` | dynamic | Reply to the VRFY command: 252 (cannot verify, accepts anyway) or 502 (refused as not implemented) |
| `dns_check_nameservers` | list | 1.1.1.1,8.8.8.8 | `MAIL_ON_RAILS_DNS_CHECK_NAMESERVERS` | dynamic | Resolvers used for domain DNS verification |

## network

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `smtp_host` | string | 0.0.0.0 | `SMTP_HOST` | static | SMTP bind address |
| `smtp_port` | integer | 1025 | `SMTP_PORT` | static | SMTP MX listener port (STARTTLS) |
| `smtp_submission_port` | integer | 1587 | `SMTP_SUBMISSION_PORT` | static | SMTP submission port (STARTTLS) |
| `smtps_port` | integer | 1465 | `SMTPS_PORT` | static | SMTP submission port (implicit TLS) |
| `imap_host` | string | 0.0.0.0 | `MAIL_ON_RAILS_HOST` | static | IMAP bind address |
| `imap_port` | integer | 1143 | `MAIL_ON_RAILS_IMAP_PORT` | static | IMAP listener port (STARTTLS) |
| `imaps_port` | integer | 1993 | `MAIL_ON_RAILS_IMAPS_PORT` | static | IMAP listener port (implicit TLS) |

## tls

| Setting | Type | Default | ENV | Scope | Description |
| --- | --- | --- | --- | --- | --- |
| `smtp_tls_cert` | string | (none) | `SMTP_TLS_CERT` | static | SMTP TLS certificate path (PEM) |
| `smtp_tls_key` | string | (none) | `SMTP_TLS_KEY` | static | SMTP TLS private key path (PEM) |
| `smtp_tls_dir` | string | storage/tls | `SMTP_TLS_DIR` | static | Directory for the self-signed development cert (SMTP) |
| `smtp_tls_hosts` | list | localhost | `SMTP_TLS_HOSTS` | static | SANs on the self-signed development cert (SMTP) |
| `imap_tls_cert` | string | (none) | `MAIL_ON_RAILS_TLS_CERT` | static | IMAP TLS certificate path (PEM) |
| `imap_tls_key` | string | (none) | `MAIL_ON_RAILS_TLS_KEY` | static | IMAP TLS private key path (PEM) |
| `imap_tls_dir` | string | storage/tls | `MAIL_ON_RAILS_TLS_DIR` | static | Directory for the self-signed development cert (IMAP) |
| `imap_tls_hosts` | list | localhost | `MAIL_ON_RAILS_TLS_HOSTS` | static | SANs on the self-signed development cert (IMAP) |
