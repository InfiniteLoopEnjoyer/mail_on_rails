# frozen_string_literal: true

require "test_helper"
require "active_job"

# The db harness loads no engine; pull in what the enrichment cache needs
# and use the test adapter (no real queue), like honeypot_event_test.
require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ip_enrichment_job", __dir__)

# The per-IP attribution cache behind the live connection pages: known
# addresses come back synchronously, unknown or stale ones get exactly one
# background lookup per debounce window, and the per-call request budget
# bounds the queue churn a page full of fresh scanner IPs can cause.
class IpEnrichmentTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    ActiveJob::Base.queue_adapter.enqueued_jobs.clear
  end

  def enqueued_ips
    ActiveJob::Base.queue_adapter.enqueued_jobs
                   .select { |job| job[:job] == MailOnRails::IpEnrichmentJob }
                   .map { |job| job[:args].first }
  end

  def test_unknown_addresses_enqueue_one_lookup_and_return_nothing
    result = MailOnRails::IpEnrichment.ensure_all([ "203.0.113.9", nil, "203.0.113.9" ])

    assert_empty result
    assert_equal [ "203.0.113.9" ], enqueued_ips
    assert MailOnRails::IpEnrichment.find_by(ip: "203.0.113.9").requested_at, "placeholder row carries the debounce stamp"

    MailOnRails::IpEnrichment.ensure_all([ "203.0.113.9" ])
    assert_equal 1, enqueued_ips.size, "a second call within the debounce enqueues nothing"
  end

  def test_fresh_rows_return_their_enrichment_without_a_lookup
    MailOnRails::IpEnrichment.create!(ip: "203.0.113.9", enrichment: { "asn" => "64496", "country" => "CA" },
                                      looked_up_at: Time.current)

    result = MailOnRails::IpEnrichment.ensure_all([ "203.0.113.9" ])

    assert_equal "64496", result["203.0.113.9"]["asn"]
    assert_empty enqueued_ips
  end

  def test_stale_rows_are_refreshed_but_still_served
    MailOnRails::IpEnrichment.create!(ip: "203.0.113.9", enrichment: { "asn" => "64496" },
                                      looked_up_at: 8.days.ago, requested_at: 8.days.ago)

    result = MailOnRails::IpEnrichment.ensure_all([ "203.0.113.9" ])

    assert_equal "64496", result["203.0.113.9"]["asn"], "stale data beats no data while the refresh runs"
    assert_equal [ "203.0.113.9" ], enqueued_ips
  end

  def test_request_budget_bounds_one_call
    ips = (1..30).map { |i| "203.0.113.#{i}" }

    MailOnRails::IpEnrichment.ensure_all(ips)

    assert_equal MailOnRails::IpEnrichment::MAX_REQUESTS_PER_CALL, enqueued_ips.size
    assert_equal ips.first(MailOnRails::IpEnrichment::MAX_REQUESTS_PER_CALL), enqueued_ips,
                 "earlier addresses win the budget"
  end

  def test_job_fills_the_row
    MailOnRails::IpEnrichment.create!(ip: "203.0.113.9", requested_at: Time.current)
    lookup = MailOnRails::CymruLookup.method(:lookup)
    MailOnRails::CymruLookup.singleton_class.define_method(:lookup) do |_ip|
      { "asn" => "64496", "rdns" => "scanner.example.net" }
    end
    begin
      MailOnRails::IpEnrichmentJob.perform_now("203.0.113.9")
    ensure
      MailOnRails::CymruLookup.singleton_class.define_method(:lookup, lookup)
    end

    row = MailOnRails::IpEnrichment.find_by(ip: "203.0.113.9")
    assert_equal "scanner.example.net", row.enrichment["rdns"]
    assert row.looked_up_at
  end

  def test_prune_removes_old_rows
    old = MailOnRails::IpEnrichment.create!(ip: "203.0.113.9")
    old.update_columns(updated_at: 31.days.ago)
    MailOnRails::IpEnrichment.create!(ip: "198.51.100.7")

    MailOnRails::IpEnrichment.prune!

    assert_equal [ "198.51.100.7" ], MailOnRails::IpEnrichment.pluck(:ip)
  end
end
