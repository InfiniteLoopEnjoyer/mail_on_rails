require "test_helper"

# The published MTA-STS policy's env-driven knobs. Mode and max_age ship
# as "testing"/86400 and are switched per deployment
# (MAIL_ON_RAILS_MTA_STS_MODE=enforce once TLS-RPT comes back clean);
# senders only re-fetch on a new policy id, so the id must move whenever
# either knob does.
class MtaStsTest < ActiveSupport::TestCase
  ENV_KEYS = %w[MAIL_ON_RAILS_MTA_STS_MODE MAIL_ON_RAILS_MTA_STS_MAX_AGE].freeze

  setup do
    @saved_env = ENV_KEYS.to_h { |k| [ k, ENV.delete(k) ] }
    Setting.smtp_helo_hostname = "mail.example.test"
  end

  teardown do
    @saved_env.each { |k, v| v ? ENV[k] = v : ENV.delete(k) }
  end

  test "defaults to testing mode with a one-day cache" do
    assert_equal "testing", MtaSts.mode
    assert_equal 86_400, MtaSts.max_age
    assert_includes MtaSts.policy, "mode: testing\r\n"
    assert_includes MtaSts.policy, "max_age: 86400\r\n"
  end

  test "enforce mode raises the default cache to a week" do
    ENV["MAIL_ON_RAILS_MTA_STS_MODE"] = "enforce"

    assert_equal "enforce", MtaSts.mode
    assert_equal 604_800, MtaSts.max_age
  end

  test "an explicit max_age overrides the mode default" do
    ENV["MAIL_ON_RAILS_MTA_STS_MODE"] = "enforce"
    ENV["MAIL_ON_RAILS_MTA_STS_MAX_AGE"] = "7200"

    assert_equal 7200, MtaSts.max_age
  end

  test "changing the mode changes the policy id, so senders re-fetch" do
    testing_id = MtaSts.policy_id
    ENV["MAIL_ON_RAILS_MTA_STS_MODE"] = "enforce"

    refute_equal testing_id, MtaSts.policy_id
    assert_match(/\A[0-9a-f]{12}\z/, MtaSts.policy_id)
  end

  test "an invalid mode names itself" do
    ENV["MAIL_ON_RAILS_MTA_STS_MODE"] = "enforced"

    error = assert_raises(ArgumentError) { MtaSts.mode }
    assert_match(/MAIL_ON_RAILS_MTA_STS_MODE/, error.message)
  end

  test "a max_age outside RFC 8461's bounds is refused" do
    ENV["MAIL_ON_RAILS_MTA_STS_MAX_AGE"] = "60"
    assert_raises(ArgumentError) { MtaSts.max_age }

    ENV["MAIL_ON_RAILS_MTA_STS_MAX_AGE"] = "not-a-number"
    assert_raises(ArgumentError) { MtaSts.max_age }
  end
end
