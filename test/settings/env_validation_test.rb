# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/settings/check"

# The ENV tier is held to the schema like the tiers written by hand: a
# string or address has to pass its setting's rule, and an integer whose
# zero would switch a guard off has a floor.
class EnvValidationTest < Minitest::Test
  Settings = MailOnRails::Settings

  def teardown
    Settings.reset!
  end

  # Fails the test if anything asks the resolver.
  def without_dns
    singleton = Resolv.singleton_class
    original = Resolv.method(:getaddresses)
    singleton.define_method(:getaddresses) { |host| raise "unexpected DNS lookup of #{host}" }
    yield
  ensure
    singleton.define_method(:getaddresses, original)
  end

  # -- floors -----------------------------------------------------------

  test "a zero collateral lookback is refused in every tier" do
    with_env("MAIL_ON_RAILS_HONEYPOT_COLLATERAL_DAYS" => "0") do
      error = assert_raises(MailOnRails::Netserv::Config::Error) { Settings[:honeypot_collateral_days] }
      assert_match(/MAIL_ON_RAILS_HONEYPOT_COLLATERAL_DAYS must be >= 1/, error.message)
    end
    assert_raises(ArgumentError) { Settings.definition(:honeypot_collateral_days).coerce("0") }
    assert_raises(ArgumentError) { Settings.overrides = { honeypot_collateral_days: 0 } }
    assert_equal 7, Settings[:honeypot_collateral_days], "the default is untouched"
  end

  test "a zero connection-history retention is refused in every tier" do
    with_env("MAIL_ON_RAILS_CONN_LOG_RETENTION_DAYS" => "0") do
      assert_raises(MailOnRails::Netserv::Config::Error) { Settings[:conn_log_retention_days] }
    end
    assert_raises(ArgumentError) { Settings.definition(:conn_log_retention_days).coerce(0) }
    assert_equal 90, Settings[:conn_log_retention_days], "the default is untouched"
  end

  test "an unusable database row for a floored setting falls back to the boot value" do
    Settings.store = -> { { "honeypot_collateral_days" => "0" } }

    assert_equal 7, Settings[:honeypot_collateral_days]
  end

  # -- strings and addresses from ENV -----------------------------------

  test "an env string that fails its setting's rule is refused, naming the variable" do
    {
      "SMTP_VRFY_RESPONSE" => [ :smtp_vrfy_response, "999" ],
      "MAILROOM_DMARC_ENFORCE" => [ :mailroom_dmarc_enforce, "sometimes" ],
      "MAIL_ON_RAILS_MTA_STS_MODE" => [ :mta_sts_mode, "enforced" ],
      "MAIL_ON_RAILS_SMARTHOST_TLS" => [ :smarthost_tls, "plaintext" ],
      "SMTP_HELO_HOST" => [ :smtp_helo_hostname, "mail.example.com\r\nX-Injected: 1" ]
    }.each do |variable, (name, value)|
      with_env(variable => value) do
        error = assert_raises(ArgumentError, variable) { Settings[name] }
        assert_match(/\A#{variable} /, error.message)
      end
    end
  end

  test "valid env strings still read as before" do
    with_env("SMTP_VRFY_RESPONSE" => "502", "MAILROOM_DMARC_ENFORCE" => "log",
             "SMTP_HELO_HOST" => " Mail.Example.COM ", "MAIL_ON_RAILS_HONEYPOT_BANNER" => "anything goes") do
      assert_equal "502", Settings[:smtp_vrfy_response]
      assert_equal "log", Settings[:mailroom_dmarc_enforce]
      assert_equal "mail.example.com", Settings[:smtp_helo_hostname]
      assert_equal "anything goes", Settings.static(:honeypot_banner), "a setting without a rule is not judged"
    end
    with_env("SMTP_HELO_HOST" => "   ") { assert_nil Settings[:smtp_helo_hostname] }
  end

  test "an env scanner address is held to the forbidden ranges and the address shape" do
    [
      [ "SMTP_CLAMAV_ADDR", :smtp_clamav_addr, "169.254.169.254:3310" ],
      [ "SMTP_CLAMAV_ADDR", :smtp_clamav_addr, "clamav:99999" ],
      [ "SMTP_RSPAMD_ADDR", :smtp_rspamd_addr, "ftp://rspamd:11333" ],
      [ "SMTP_RSPAMD_ADDR", :smtp_rspamd_addr, "http://100.100.100.200:11333" ],
      [ "SMTP_RSPAMD_CONTROLLER_ADDR", :smtp_rspamd_controller_addr, "https://169.254.169.254:11334" ],
      [ "SMTP_RSPAMD_CONTROLLER_ADDR", :smtp_rspamd_controller_addr, "http://:11334" ]
    ].each do |variable, name, value|
      with_env(variable => value) do
        without_dns { assert_raises(ArgumentError, value) { Settings[name] } }
      end
    end
  end

  # A boot must not wait on, or be decided by, the resolver: the hostname
  # lookup belongs to the settings UI tier.
  test "an env scanner hostname is checked for shape only, without a DNS lookup" do
    without_dns do
      with_env("SMTP_CLAMAV_ADDR" => "mail_on_rails-clamav:3310", "SMTP_RSPAMD_ADDR" => "rspamd:11333",
               "SMTP_RSPAMD_CONTROLLER_ADDR" => "https://rspamd.internal:11334") do
        assert_equal "mail_on_rails-clamav:3310", Settings[:smtp_clamav_addr]
        assert_equal "rspamd:11333", Settings[:smtp_rspamd_addr]
        assert_equal "https://rspamd.internal:11334", Settings[:smtp_rspamd_controller_addr]
        assert Settings.validate_env!
      end
      with_env("SMTP_CLAMAV_ADDR" => "not a host:3310") do
        assert_raises(ArgumentError) { Settings[:smtp_clamav_addr] }
      end
    end
  end

  # The value the deploy template ships has to be writable from the UI too.
  test "a container-style hostname with an underscore passes the database tier" do
    singleton = Resolv.singleton_class
    original = Resolv.method(:getaddresses)
    singleton.define_method(:getaddresses) { |_host| [ "172.18.0.5" ] }

    assert_equal "mail_on_rails-clamav:3310", Settings.definition(:smtp_clamav_addr).coerce("mail_on_rails-clamav:3310")
    assert_raises(ArgumentError) { Settings.definition(:smtp_helo_hostname).coerce("mail_on_rails.example.com") }
  ensure
    singleton.define_method(:getaddresses, original)
  end

  test "the env verdict follows the variable when it changes" do
    with_env("SMTP_VRFY_RESPONSE" => "999") { assert_raises(ArgumentError) { Settings[:smtp_vrfy_response] } }
    with_env("SMTP_VRFY_RESPONSE" => "502") { assert_equal "502", Settings[:smtp_vrfy_response] }
    with_env("SMTP_VRFY_RESPONSE" => "999") { assert_raises(ArgumentError) { Settings[:smtp_vrfy_response] } }
  end

  test "validate_env! fails the boot on a bad env string with the config error class" do
    with_env("SMTP_VRFY_RESPONSE" => "999") do
      error = assert_raises(MailOnRails::Netserv::Config::Error) { Settings.validate_env! }
      assert_match(/SMTP_VRFY_RESPONSE must be 252 or 502, got "999"/, error.message)
    end
    assert Settings.validate_env!
  end

  test "check reports a bad env string as an error" do
    with_env("MAILROOM_DMARC_ENFORCE" => "sometimes") do
      check = Settings::Check.new

      assert_not check.ok?
      assert(check.errors.any? { |error| error.include?("MAILROOM_DMARC_ENFORCE") }, check.errors.inspect)
    end
  end
end
