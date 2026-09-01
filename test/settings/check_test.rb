# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/settings/check"

# Settings::Check's production posture report: the defaults enforce, so
# each warning fires only where a deployment has weakened a knob - and
# every weakening that matters has a warning. Rails is stood in for
# (Check only asks whether the environment is production).
class CheckTest < Minitest::Test
  Settings = MailOnRails::Settings

  module FakeRails
    def self.env
      @env ||= Struct.new(:production) { def production? = production }.new(true)
    end
  end

  def setup
    Object.const_set(:Rails, FakeRails) unless defined?(::Rails)
  end

  def teardown
    Settings.reset!
    Object.send(:remove_const, :Rails) if defined?(::Rails) && ::Rails.equal?(FakeRails)
  end

  def warnings(overrides = {})
    Settings.overrides = overrides
    Settings::Check.new.warnings
  end

  def assert_warned(pattern, overrides)
    assert warnings(overrides).any? { |w| w.match?(pattern) },
           "expected a warning matching #{pattern.inspect} for #{overrides.inspect}; got #{warnings(overrides).inspect}"
  end

  test "the enforcing defaults raise none of the weakening warnings" do
    baseline = warnings(smtp_rbl_zones: [ "zen.spamhaus.org" ], smtp_clamav_addr: "clamav:3310")
    %w[APPEND MTA-STS DANE BIMI mailroom_seal_max_age].each do |subject|
      refute baseline.any? { |w| w.include?(subject) }, "defaults must not warn about #{subject}: #{baseline.inspect}"
    end
  end

  test "a disabled imap_append_fail_closed is called out" do
    assert_warned(/IMAP APPEND stores mail unscanned/, imap_append_fail_closed: false)
  end

  test "disabled MTA-STS, DANE and BIMI are each called out" do
    assert_warned(/MTA-STS policies are ignored/, mta_sts: false)
    assert_warned(/DANE\/TLSA records are ignored/, dane: false)
    assert_warned(/BIMI logo display is off/, bimi: false)
  end

  test "an unusually large seal lifetime is called out, a recovery-sized one is not" do
    assert_warned(/mailroom_seal_max_age is 691200s \(8 days\)/, mailroom_seal_max_age: 8 * 86_400)
    refute warnings(mailroom_seal_max_age: 86_400).any? { |w| w.include?("mailroom_seal_max_age") }
  end

  test "zeroed listener knobs are a schema error, not a posture warning" do
    with_env("SMTP_CONN_RATE" => "0", "MAIL_ON_RAILS_IMAP_SESSION_SECONDS" => "0") do
      check = Settings::Check.new
      refute check.ok?
      assert check.errors.any? { |e| e.include?("SMTP_CONN_RATE") }
      assert check.errors.any? { |e| e.include?("MAIL_ON_RAILS_IMAP_SESSION_SECONDS") }
    end
  end

  test "outside production the posture checks are silent" do
    FakeRails.env.production = false
    begin
      refute warnings(dane: false, mta_sts: false).any? { |w| w.match?(/DANE|MTA-STS/) }
    ensure
      FakeRails.env.production = true
    end
  end
end
