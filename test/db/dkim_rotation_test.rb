# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/rotate_dkim_keys_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# The DKIM rotation lifecycle: stage a new key under a fresh selector,
# promote only once its TXT is visible in public DNS, revoke the retired
# selector (empty p=) after the grace window.
class DkimRotationTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    @domain = MailOnRails::Domain.create!(name: "example.test")
  end

  class FakeResolver
    def initialize(txt = {}) = @txt = txt
    def txt(name) = @txt[name]
  end

  # Records enough of the Cloudflare surface for the job's staging and
  # revocation calls.
  class FakeCloudflare
    attr_reader :created, :updated

    def initialize(records: {})
      @records = records # name => [{"id" => ..., "content" => ...}]
      @created = []
      @updated = []
    end

    def zone_id(_name) = "zone-1"
    def records(_zone, type:, name:) = Array(@records[name])

    def create_record(_zone, attrs)
      @created << attrs
    end

    def update_record(_zone, record_id, attrs)
      @updated << attrs.merge(id: record_id)
    end
  end

  def with_cloudflare_enabled
    previous = ENV["CLOUDFLARE_API_TOKEN"]
    ENV["CLOUDFLARE_API_TOKEN"] = "test-token"
    yield
  ensure
    previous ? ENV["CLOUDFLARE_API_TOKEN"] = previous : ENV.delete("CLOUDFLARE_API_TOKEN")
  end

  test "selector falls back to the static setting until a rotation happens" do
    assert_equal "rail", @domain.dkim_selector
    assert_equal "rail._domainkey.example.test", @domain.dkim_txt_name
  end

  test "stage mints a dated selector and key; promote swaps and retires" do
    old_key = @domain.dkim_private_key
    @domain.stage_dkim_rotation!

    assert @domain.dkim_staged?
    assert_match(/\Arail-\d{8}\z/, @domain.dkim_next_selector)
    assert_match(/p=[A-Za-z0-9+\/]/, @domain.dkim_next_txt_value)
    staged_selector = @domain.dkim_next_selector
    @domain.stage_dkim_rotation!
    assert_equal staged_selector, @domain.dkim_next_selector, "restaging must be a no-op"

    @domain.promote_dkim_rotation!
    assert_equal staged_selector, @domain.dkim_selector
    refute_equal old_key, @domain.dkim_private_key
    assert_equal "rail", @domain.dkim_retired_selector
    assert @domain.dkim_rotated_at.present?
    assert_not @domain.dkim_staged?
  end

  test "promote without a staged key raises" do
    assert_raises(ArgumentError) { @domain.promote_dkim_rotation! }
  end

  test "rotation_due? respects age, staging, and the 0 default" do
    @domain.update!(created_at: 200.days.ago)
    assert_not @domain.dkim_rotation_due?(0), "0 means manual - never due"
    assert @domain.dkim_rotation_due?(180)
    @domain.update!(dkim_rotated_at: 1.day.ago)
    assert_not @domain.dkim_rotation_due?(180)
  end

  test "job promotes only once public DNS shows the staged key" do
    @domain.stage_dkim_rotation!
    name = @domain.dkim_next_txt_name

    MailOnRails::RotateDkimKeysJob.new.perform(resolver: FakeResolver.new(name => []))
    assert_not @domain.reload.dkim_rotated_at, "an invisible TXT must not promote"

    MailOnRails::RotateDkimKeysJob.new.perform(resolver: FakeResolver.new(name => [ @domain.dkim_next_txt_value ]))
    assert @domain.reload.dkim_rotated_at, "a visible TXT must promote"
    assert_equal "rail", @domain.dkim_retired_selector
  end

  test "job stages and publishes when due, and revokes retired selectors past grace" do
    with_cloudflare_enabled do
      MailOnRails::Settings.overrides = { dkim_rotation_days: 30 }
      @domain.update!(created_at: 60.days.ago)
      fake = FakeCloudflare.new

      MailOnRails::RotateDkimKeysJob.new.perform(resolver: FakeResolver.new, client: fake)

      assert @domain.reload.dkim_staged?
      assert_equal 1, fake.created.size
      assert_equal @domain.dkim_next_txt_name, fake.created.first[:name]

      # Now a retired selector past grace: it gets an empty-p= revocation.
      @domain.update!(dkim_retired_selector: "rail-old", dkim_retired_at: 8.days.ago)
      revoking = FakeCloudflare.new(records: { @domain.dkim_retired_txt_name => [ { "id" => "r1", "content" => "old" } ] })
      MailOnRails::RotateDkimKeysJob.new.perform(resolver: FakeResolver.new, client: revoking)

      assert_equal %("v=DKIM1; p="), revoking.updated.first[:content]
      assert_nil @domain.reload.dkim_retired_selector
    end
  ensure
    MailOnRails::Settings.reset!
  end

  test "job without cloudflare never auto-stages but clears expired retirees with a warning" do
    MailOnRails::Settings.overrides = { dkim_rotation_days: 30 }
    @domain.update!(created_at: 60.days.ago, dkim_retired_selector: "rail-old", dkim_retired_at: 8.days.ago)

    MailOnRails::RotateDkimKeysJob.new.perform(resolver: FakeResolver.new)

    assert_not @domain.reload.dkim_staged?, "auto-staging needs somewhere to publish"
    assert_nil @domain.dkim_retired_selector
  ensure
    MailOnRails::Settings.reset!
  end
end
