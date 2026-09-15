# frozen_string_literal: true

require "test_helper"
require "active_job"

# The gem's jobs normally load via the engine; the db harness loads none, so
# pull in what HoneypotEvent's enrichment enqueue needs and use the test
# adapter (no real queue).
require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/honeypot_enrichment_job", __dir__)

# The multi-tenant-safe response ladder: a canary login earns a *temporary*,
# auto-expiring IP throttle - never a permanent ban - and only when the address
# is neither allowlisted nor shared with a real tenant. Probes are observed
# only, unless the operator switched protocol_auto_ban on - then they earn the
# same permanent BannedIp a failed login does under auth_auto_ban.
class HoneypotEventTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    ActiveJob::Base.queue_adapter.enqueued_jobs.clear
    @allowlist_before = ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"]
    ENV.delete("MAIL_ON_RAILS_PROTOCOL_AUTO_BAN")
  end

  def teardown
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = @allowlist_before
    ENV.delete("MAIL_ON_RAILS_PROTOCOL_AUTO_BAN")
  end

  def enable_protocol_auto_ban = ENV["MAIL_ON_RAILS_PROTOCOL_AUTO_BAN"] = "1"

  def bans = MailOnRails::BannedIp.order(:cidr).pluck(:cidr, :source, :note)

  def record(ip: "203.0.113.7", trigger: "canary_auth", **extra)
    MailOnRails::HoneypotEvent.record({ protocol: "smtp", trigger: trigger, ip: ip,
                                        occurred_at: Time.current }.merge(extra))
  end

  def blocked?(ip)
    MailOnRails::AuthThrottle.check(ip: ip, email: nil).present?
  end

  def test_a_canary_login_temporarily_throttles_the_source_without_a_permanent_ban
    event = record(ip: "203.0.113.7", trigger: "canary_auth")

    assert blocked?("203.0.113.7"), "the source should be temporarily throttled"
    assert_equal 0, MailOnRails::BannedIp.count, "no permanent ban is ever automatic"
    assert_match(/throttled/, event.reload.response)
  end

  def test_the_temporary_block_expires_on_its_own
    record(ip: "203.0.113.7", trigger: "canary_auth")
    row = MailOnRails::AuthThrottle.find_by(scope: "ip", key: "203.0.113.7")

    assert row.blocked_until.present?
    assert_operator row.blocked_until, :<=, MailOnRails::HoneypotEvent.block_seconds.seconds.from_now + 5
  end

  def test_an_exploit_probe_is_observed_only
    event = record(ip: "203.0.113.7", trigger: "exploit_probe", signature: "exim_run")

    assert_not blocked?("203.0.113.7"), "a regex match must not auto-throttle"
    assert_equal "observed", event.reload.response
  end

  def test_a_foreign_protocol_or_garbage_hit_is_observed_only_by_default
    http = record(ip: "203.0.113.7", trigger: "foreign_protocol", signature: "http_request")
    junk = record(ip: "203.0.113.8", trigger: "garbage", signature: "control_bytes")

    assert_equal "observed", http.reload.response
    assert_equal "observed", junk.reload.response
    assert_not blocked?("203.0.113.7")
    assert_empty bans
  end

  def test_protocol_auto_ban_bans_a_probe_source_permanently
    enable_protocol_auto_ban
    event = record(ip: "203.0.113.7", trigger: "foreign_protocol", signature: "http_request")

    assert_equal "banned 203.0.113.7", event.reload.response
    assert_equal [ [ "203.0.113.7", "protocol_abuse", "auto: http request on smtp" ] ], bans
    assert MailOnRails::BannedIp.covering("203.0.113.7")
  end

  def test_protocol_auto_ban_covers_every_probe_type_trigger_but_not_a_canary_login
    enable_protocol_auto_ban
    record(ip: "203.0.113.1", trigger: "exploit_probe", signature: "exim_run")
    record(ip: "203.0.113.2", trigger: "garbage", signature: "invalid_utf8", protocol: "imap")
    canary = record(ip: "203.0.113.3", trigger: "canary_auth")

    assert_equal [ [ "203.0.113.1", "protocol_abuse", "auto: exim run on smtp" ],
                   [ "203.0.113.2", "protocol_abuse", "auto: invalid utf8 on imap" ] ], bans
    assert_match(/throttled/, canary.reload.response, "a canary login keeps its temporary throttle")
  end

  def test_protocol_auto_ban_names_the_misconfigured_client_case_on_a_tls_handshake
    enable_protocol_auto_ban
    record(ip: "203.0.113.7", trigger: "foreign_protocol", signature: "tls_handshake", protocol: "imap")

    assert_match(/tls handshake on imap \(a mail client on the wrong port/, bans.first.last)
  end

  def test_protocol_auto_ban_honours_the_allowlist_but_not_a_shared_address
    enable_protocol_auto_ban
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = "203.0.113.0/24"
    listed = record(ip: "203.0.113.7", trigger: "garbage", signature: "control_bytes")
    assert_equal "allowlisted", listed.reload.response

    MailOnRails::ClosedConnection.create!(protocol: "imap", ip: "198.51.100.9",
                                          username: "real@example.test", closed_at: 1.hour.ago)
    shared = record(ip: "198.51.100.9", trigger: "garbage", signature: "control_bytes")
    assert_equal "banned 198.51.100.9", shared.reload.response, "the operator chose no exceptions"

    assert_equal [ "198.51.100.9" ], bans.map(&:first)
  end

  def test_protocol_auto_ban_reports_an_address_that_is_already_banned
    enable_protocol_auto_ban
    MailOnRails::BannedIp.create!(cidr: "203.0.113.0/24", source: "manual")
    event = record(ip: "203.0.113.7", trigger: "foreign_protocol", signature: "http_request")

    assert_equal "already banned", event.reload.response
    assert_equal 1, MailOnRails::BannedIp.count
  end

  def test_protocol_auto_ban_keys_an_ipv6_source_on_its_64
    enable_protocol_auto_ban
    event = record(ip: "2001:db8:1:2::7", trigger: "garbage", signature: "control_bytes")

    assert_equal "banned 2001:db8:1:2::/64", event.reload.response
    assert MailOnRails::BannedIp.covering("2001:db8:1:2::8")
    assert_nil MailOnRails::BannedIp.covering("2001:db8:1:3::7")
  end

  def test_an_allowlisted_source_is_never_throttled
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = "203.0.113.0/24"
    event = record(ip: "203.0.113.7", trigger: "canary_auth")

    assert_not blocked?("203.0.113.7")
    assert_equal "allowlisted", event.reload.response
  end

  def test_a_shared_address_carrying_real_traffic_is_left_alone
    # A real (non-canary) tenant recently authenticated from this IP.
    MailOnRails::ClosedConnection.create!(protocol: "imap", ip: "203.0.113.7",
                                          username: "real@example.test", closed_at: 1.hour.ago)
    event = record(ip: "203.0.113.7", trigger: "canary_auth")

    assert_not blocked?("203.0.113.7"), "a shared address must not be blocked over one attacker"
    assert_equal "observed (shared address)", event.reload.response
  end

  def test_an_ipv6_canary_hit_throttles_the_whole_64_and_defers_to_tenants_anywhere_in_it
    event = record(ip: "2001:db8:1:2::7", trigger: "canary_auth")

    assert blocked?("2001:db8:1:2::8"), "the block lands on the /64 the attacker owns"
    assert_not blocked?("2001:db8:1:3::7")
    assert_match(/throttled/, event.reload.response)

    # A real tenant elsewhere in another /64 marks THAT /64 shared.
    MailOnRails::ClosedConnection.create!(protocol: "imap", ip: "2001:db8:1:3::abcd",
                                          username: "real@example.test", closed_at: 1.hour.ago)
    shared = record(ip: "2001:db8:1:3::7", trigger: "canary_auth")

    assert_not blocked?("2001:db8:1:3::7"), "a /64 carrying tenant traffic must not be blocked"
    assert_equal "observed (shared address)", shared.reload.response
  end

  def test_a_canary_accounts_own_traffic_does_not_mark_the_address_shared
    MailOnRails::EmailAccount.create!(email: "canary@example.test", password: "secret123", honeypot: true)
    MailOnRails::ClosedConnection.create!(protocol: "imap", ip: "203.0.113.7",
                                          username: "canary@example.test", closed_at: 1.hour.ago)
    record(ip: "203.0.113.7", trigger: "canary_auth")

    assert blocked?("203.0.113.7"), "only a real tenant's traffic protects the address"
  end

  def test_enrichment_is_enqueued_for_every_event
    event = record(ip: "203.0.113.7")

    jobs = ActiveJob::Base.queue_adapter.enqueued_jobs
    assert_equal 1, jobs.size
    assert_equal MailOnRails::HoneypotEnrichmentJob, jobs.first[:job]
    assert_equal [ event.id ], jobs.first[:args]
  end

  def test_an_event_without_an_ip_is_observed_only
    event = record(ip: nil)

    assert_equal 1, MailOnRails::HoneypotEvent.count
    assert_equal "observed", event.reload.response
    assert_empty ActiveJob::Base.queue_adapter.enqueued_jobs
  end

  def test_record_never_raises_on_a_bad_payload
    assert_nil MailOnRails::HoneypotEvent.record(protocol: "smtp", trigger: "bogus", ip: "203.0.113.7")
    assert_equal 0, MailOnRails::HoneypotEvent.count
  end

  def test_prune_drops_events_past_retention
    old = record(ip: "203.0.113.7")
    old.update_columns(occurred_at: 400.days.ago)
    record(ip: "203.0.113.8")

    MailOnRails::HoneypotEvent.prune!
    assert_equal 1, MailOnRails::HoneypotEvent.count
  end
end
