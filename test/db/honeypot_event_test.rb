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
# only. Permanent bans stay a human decision.
class HoneypotEventTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    ActiveJob::Base.queue_adapter.enqueued_jobs.clear
    @allowlist_before = ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"]
  end

  def teardown
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = @allowlist_before
  end

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
