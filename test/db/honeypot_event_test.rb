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
  ENV_KEYS = %w[MAIL_ON_RAILS_PROTOCOL_AUTO_BAN MAIL_ON_RAILS_HONEYPOT_MAX_EVENTS_PER_IP
                MAIL_ON_RAILS_HONEYPOT_CAP_WINDOW].freeze

  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    ActiveJob::Base.queue_adapter.enqueued_jobs.clear
    @allowlist_before = ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"]
    ENV_KEYS.each { |key| ENV.delete(key) }
  end

  def teardown
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = @allowlist_before
    ENV_KEYS.each { |key| ENV.delete(key) }
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

  def test_protocol_auto_ban_honours_the_allowlist
    enable_protocol_auto_ban
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = "203.0.113.0/24"
    listed = record(ip: "203.0.113.7", trigger: "garbage", signature: "control_bytes")
    assert_equal "allowlisted", listed.reload.response
    assert_empty bans
  end

  # The audit's M3: a probe signature is a regex, and a third party's MX
  # relaying mail to "${run{/bin/sh}}"@hosted.example matches it. An
  # address that logged in or delivered mail lately is a working peer, not
  # a scanner - the event is recorded, the ban is not written.
  def test_protocol_auto_ban_spares_an_address_that_did_real_mail_work_lately
    enable_protocol_auto_ban
    MailOnRails::ClosedConnection.create!(protocol: "imap", ip: "198.51.100.9",
                                          username: "real@example.test", closed_at: 1.hour.ago)
    MailOnRails::ClosedConnection.create!(protocol: "smtp", ip: "198.51.100.10", messages: 2, closed_at: 1.hour.ago)
    tenant = record(ip: "198.51.100.9", trigger: "garbage", signature: "control_bytes")
    relay = record(ip: "198.51.100.10", trigger: "exploit_probe", signature: "exim_run")

    assert_equal "observed (shared address)", tenant.reload.response
    assert_equal "observed (shared address)", relay.reload.response, "a delivering MX is spared like a tenant"
    assert_empty bans
    assert_equal 2, MailOnRails::HoneypotEvent.count, "the probes themselves are still recorded"
    assert_nil MailOnRails::BannedIp.auto_ban_for_probe(ip: "198.51.100.10", protocol: "smtp", trigger: "exploit_probe")
  end

  def test_protocol_auto_ban_spares_an_address_with_a_working_session_open_right_now
    enable_protocol_auto_ban
    listener = MailOnRails::Listener.create!(listener_id: "smtp-test", protocol: "smtp",
                                              started_at: 1.hour.ago, heartbeat_at: Time.current)
    MailOnRails::OpenConnection.replace_for!(listener.listener_id, "smtp",
                                             [ { connection_id: 1, peer_ip: "198.51.100.11", port: 25,
                                                 connected_at: Time.current, messages: 1 } ])
    event = record(ip: "198.51.100.11", trigger: "exploit_probe", signature: "exim_run")

    assert_equal "observed (shared address)", event.reload.response
    assert_empty bans
  end

  def test_work_older_than_the_collateral_lookback_no_longer_spares_the_address
    enable_protocol_auto_ban
    MailOnRails::ClosedConnection.create!(protocol: "imap", ip: "198.51.100.9",
                                          username: "real@example.test", closed_at: 30.days.ago)
    event = record(ip: "198.51.100.9", trigger: "garbage", signature: "control_bytes")

    assert_equal "banned 198.51.100.9", event.reload.response
  end

  def test_a_canary_login_is_not_mail_work_for_the_probe_exemption
    enable_protocol_auto_ban
    MailOnRails::EmailAccount.create!(email: "canary@example.test", password: "secret123", honeypot: true)
    MailOnRails::ClosedConnection.create!(protocol: "imap", ip: "198.51.100.9",
                                          username: "canary@example.test", closed_at: 1.hour.ago)
    event = record(ip: "198.51.100.9", trigger: "garbage", signature: "control_bytes")

    assert_equal "banned 198.51.100.9", event.reload.response
  end

  # L9: behind a userland proxy or a Docker bridge every client arrives as
  # the gateway; one probe from it must not ban them all.
  def test_protocol_auto_ban_never_bans_a_local_address
    enable_protocol_auto_ban
    [ "172.18.0.1", "127.0.0.1", "10.0.0.4", "fd46:7ac3:4fd7::1", "::ffff:192.168.1.9" ].each do |ip|
      event = record(ip: ip, trigger: "foreign_protocol", signature: "http_request")
      assert_equal "observed (local address)", event.reload.response, ip
    end

    assert_empty bans
    assert_equal 5, MailOnRails::HoneypotEvent.count, "still recorded"
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

  def test_enrichment_is_enqueued_for_an_address_the_cache_does_not_know
    event = record(ip: "203.0.113.7")

    jobs = ActiveJob::Base.queue_adapter.enqueued_jobs
    assert_equal 1, jobs.size
    assert_equal MailOnRails::HoneypotEnrichmentJob, jobs.first[:job]
    assert_equal [ event.id ], jobs.first[:args]
  end

  # M5: one Cymru lookup per address, not per event. A fresh cache row is
  # copied onto the event on the connection thread (one indexed read); a
  # stale one still gets the job.
  def test_a_fresh_cache_row_fills_the_event_without_a_job
    MailOnRails::IpEnrichment.create!(ip: "203.0.113.7", enrichment: { "asn" => "64496", "country" => "CA" },
                                      looked_up_at: 1.hour.ago)
    fresh = record(ip: "203.0.113.7")
    assert_equal "64496", fresh.reload.enrichment["asn"]
    assert_empty ActiveJob::Base.queue_adapter.enqueued_jobs

    MailOnRails::IpEnrichment.create!(ip: "203.0.113.8", enrichment: { "asn" => "64497" }, looked_up_at: 9.days.ago)
    stale = record(ip: "203.0.113.8")
    assert_nil stale.reload.enrichment
    assert_equal [ [ stale.id ] ], ActiveJob::Base.queue_adapter.enqueued_jobs.map { |job| job[:args] }
  end

  def with_cymru_lookup
    calls = []
    original = MailOnRails::CymruLookup.method(:lookup)
    MailOnRails::CymruLookup.singleton_class.define_method(:lookup) do |ip|
      calls << ip
      { "asn" => "64496", "rdns" => "scanner.example.net" }
    end
    yield calls
  ensure
    MailOnRails::CymruLookup.singleton_class.define_method(:lookup, original)
  end

  def test_the_enrichment_job_looks_an_address_up_once_and_fills_the_cache_for_the_next_event
    first = record(ip: "203.0.113.7")
    second = record(ip: "203.0.113.7")

    with_cymru_lookup do |calls|
      MailOnRails::HoneypotEnrichmentJob.perform_now(first.id)
      MailOnRails::HoneypotEnrichmentJob.perform_now(second.id)

      assert_equal [ "203.0.113.7" ], calls, "the second job reads the cache the first one filled"
    end
    assert_equal "scanner.example.net", first.reload.enrichment["rdns"]
    assert_equal "scanner.example.net", second.reload.enrichment["rdns"]
    cache = MailOnRails::IpEnrichment.find_by(ip: "203.0.113.7")
    assert_equal "64496", cache.enrichment["asn"]
    assert cache.looked_up_at

    third = record(ip: "203.0.113.7")
    assert_equal "64496", third.reload.enrichment["asn"], "and a third hit needs no job at all"
  end

  # -- the per-source cap (M5) ---------------------------------------------

  def test_hits_past_the_cap_are_not_stored_and_the_last_stored_row_says_so
    ENV["MAIL_ON_RAILS_HONEYPOT_MAX_EVENTS_PER_IP"] = "3"
    stored = 3.times.map { record(ip: "203.0.113.7", trigger: "exploit_probe", signature: "exim_run") }
    assert stored.all?

    assert_nil record(ip: "203.0.113.7", trigger: "garbage", signature: "control_bytes")
    assert_nil record(ip: "203.0.113.7", trigger: "garbage", signature: "control_bytes")

    assert_equal 3, MailOnRails::HoneypotEvent.count
    assert_equal "observed #{MailOnRails::HoneypotEvent::CAP_MARKER}", stored.last.reload.response
    assert_equal "observed", stored.first.reload.response, "only the newest row carries the marker"
    assert_equal 3, ActiveJob::Base.queue_adapter.enqueued_jobs.size, "no job for a hit that was not stored"

    other = record(ip: "203.0.113.8", trigger: "garbage", signature: "control_bytes")
    assert other, "the cap is per source"
  end

  def test_the_cap_window_slides
    ENV["MAIL_ON_RAILS_HONEYPOT_MAX_EVENTS_PER_IP"] = "2"
    ENV["MAIL_ON_RAILS_HONEYPOT_CAP_WINDOW"] = "3600"
    t0 = Time.current
    2.times { record(ip: "203.0.113.7", occurred_at: t0 - 2.hours) }
    assert record(ip: "203.0.113.7", occurred_at: t0), "old hits have aged out of the window"
    assert record(ip: "203.0.113.7", occurred_at: t0 + 1)
    assert_nil record(ip: "203.0.113.7", occurred_at: t0 + 2)
  end

  def test_the_cap_counts_an_ipv6_source_per_64_however_the_host_bits_are_spelled
    ENV["MAIL_ON_RAILS_HONEYPOT_MAX_EVENTS_PER_IP"] = "2"
    assert record(ip: "2001:db8:1:2::7")
    assert record(ip: "2001:DB8:0001:0002:abcd:0:0:1"), "stored canonically"
    assert_nil record(ip: "2001:db8:1:2:ffff::9"), "the /64 is full"
    assert record(ip: "2001:db8:1:3::7"), "the neighbouring /64 is not"

    assert_equal %w[2001:db8:1:2::7 2001:db8:1:2:abcd::1 2001:db8:1:3::7],
                 MailOnRails::HoneypotEvent.order(:id).pluck(:ip)
  end

  # A /64 whose prefix holds a zero group cannot be matched exactly on the
  # compressed spelling; the coarser prefix counts the neighbourhood in,
  # which only ever makes the cap bite sooner.
  def test_the_cap_is_conservative_for_a_prefix_containing_a_zero_group
    ENV["MAIL_ON_RAILS_HONEYPOT_MAX_EVENTS_PER_IP"] = "2"
    assert record(ip: "2001:db8:0:0:1::")
    assert record(ip: "2001:db8::7")
    assert_nil record(ip: "2001:db8:0:0:2::"), "the same /64, full"
    assert_nil record(ip: "2001:db8:0:5::1"), "a neighbour in the coarse prefix is counted in, never out"
    assert record(ip: "2001:db9::1")
  end

  def test_the_cap_ignores_events_without_an_address
    ENV["MAIL_ON_RAILS_HONEYPOT_MAX_EVENTS_PER_IP"] = "1"
    3.times { assert record(ip: nil) }
    assert_equal 3, MailOnRails::HoneypotEvent.count
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
