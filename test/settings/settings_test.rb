# frozen_string_literal: true

require_relative "test_helper"

class SettingsTest < Minitest::Test
  Settings = MailOnRails::Settings

  def teardown
    Settings.reset!
  end

  # -- defaults and ENV tier -------------------------------------------

  test "defaults resolve without any configuration" do
    with_env("SMTP_MAX_CONN" => nil) do
      assert_equal 100, Settings[:smtp_max_conn]
      assert_equal :default, Settings.provenance(:smtp_max_conn)
    end
  end

  test "env overrides the default with legacy names" do
    with_env("SMTP_MAX_CONN" => "42") do
      assert_equal 42, Settings[:smtp_max_conn]
      assert_equal :env, Settings.provenance(:smtp_max_conn)
    end
  end

  test "bad env integer raises the Netserv::Config message" do
    with_env("SMTP_MAX_CONN" => "lots") do
      error = assert_raises(MailOnRails::Netserv::Config::Error) { Settings[:smtp_max_conn] }
      assert_match(/SMTP_MAX_CONN must be an integer/, error.message)
    end
  end

  test "env integer bounds are enforced" do
    with_env("SMTP_MAX_CONN" => "0") do
      assert_raises(MailOnRails::Netserv::Config::Error) { Settings[:smtp_max_conn] }
    end
  end

  test "validate_env! surfaces any bad declared variable" do
    with_env("MAIL_ON_RAILS_IMAP_MAX_CONN" => "many") do
      assert_raises(MailOnRails::Netserv::Config::Error) { Settings.validate_env! }
    end
    assert Settings.validate_env!
  end

  # -- legacy boolean semantics ----------------------------------------

  test "default-on boolean is disabled only by literal 0" do
    with_env("SMTP_SENDER_AUTH" => nil) { assert_equal true, Settings[:smtp_sender_auth] }
    with_env("SMTP_SENDER_AUTH" => "0") { assert_equal false, Settings[:smtp_sender_auth] }
    with_env("SMTP_SENDER_AUTH" => "false") { assert_equal true, Settings[:smtp_sender_auth] }
    with_env("SMTP_SENDER_AUTH" => "no") { assert_equal true, Settings[:smtp_sender_auth] }
    # DMARC enforcement joined the default-on set with the hardened
    # defaults - the asymmetric spelling rule follows the default.
    with_env("SMTP_DMARC_ENFORCE" => nil) { assert_equal true, Settings[:smtp_dmarc_enforce] }
    with_env("SMTP_DMARC_ENFORCE" => "0") { assert_equal false, Settings[:smtp_dmarc_enforce] }
  end

  test "default-off boolean is enabled only by literal 1" do
    with_env("SMTP_TRACE" => nil) { assert_equal false, Settings[:smtp_trace] }
    with_env("SMTP_TRACE" => "1") { assert_equal true, Settings[:smtp_trace] }
    with_env("SMTP_TRACE" => "true") { assert_equal false, Settings[:smtp_trace] }
    with_env("SMTP_TRACE" => "yes") { assert_equal false, Settings[:smtp_trace] }
  end

  # -- lists and strings -----------------------------------------------

  test "list env parses comma and space separated entries" do
    with_env("SMTP_RBLS" => "zen.spamhaus.org, bl.example.org  extra.example") do
      assert_equal %w[zen.spamhaus.org bl.example.org extra.example], Settings[:smtp_rbl_zones]
    end
    with_env("SMTP_RBLS" => nil) { assert_equal [], Settings[:smtp_rbl_zones] }
  end

  test "helo hostname env is normalized and nil when unset" do
    with_env("SMTP_HELO_HOST" => nil) { assert_nil Settings[:smtp_helo_hostname] }
    with_env("SMTP_HELO_HOST" => "  Mail.Example.COM ") do
      assert_equal "mail.example.com", Settings[:smtp_helo_hostname]
    end
    with_env("SMTP_HELO_HOST" => "   ") { assert_nil Settings[:smtp_helo_hostname] }
  end

  test "honeypot banner blank means nil" do
    with_env("MAIL_ON_RAILS_HONEYPOT_BANNER" => "") { assert_nil Settings.static(:honeypot_banner) }
    with_env("MAIL_ON_RAILS_HONEYPOT_BANNER" => "Exim 4.87") do
      assert_equal "Exim 4.87", Settings.static(:honeypot_banner)
    end
  end

  # -- initializer tier -------------------------------------------------

  test "overrides beat env and are typed" do
    with_env("SMTP_MAX_CONN" => "42") do
      Settings.overrides = { smtp_max_conn: "77", smtp_sender_auth: false }
      assert_equal 77, Settings[:smtp_max_conn]
      assert_equal false, Settings[:smtp_sender_auth]
      assert_equal :initializer, Settings.provenance(:smtp_max_conn)
    end
  end

  test "overrides reject unknown names and junk values eagerly" do
    assert_raises(ArgumentError) { Settings.overrides = { smtp_maxx_conn: 5 } }
    error = assert_raises(ArgumentError) { Settings.overrides = { smtp_max_conn: "lots" } }
    assert_match(/smtp_max_conn/, error.message)
    assert_raises(ArgumentError) { Settings.overrides = { smtp_max_conn: 0 } }
    assert_raises(ArgumentError) { Settings.overrides = { smtp_helo_hostname: "not a host!" } }
  end

  test "smtp_vrfy_response accepts only the two sanctioned reply codes" do
    assert_equal "252", Settings[:smtp_vrfy_response]
    Settings.overrides = { smtp_vrfy_response: "502" }
    assert_equal "502", Settings[:smtp_vrfy_response]
    error = assert_raises(ArgumentError) { Settings.overrides = { smtp_vrfy_response: "250" } }
    assert_match(/must be 252 or 502/, error.message)
  end

  test "static reads ignore the dynamic tier and unknown names raise" do
    assert_equal 1025, Settings.static(:smtp_port)
    assert_raises(ArgumentError) { Settings[:nonexistent_setting] }
    assert_raises(ArgumentError) { Settings.static(:nonexistent_setting) }
  end

  # -- DB tier through a fake store -------------------------------------

  test "db overrides beat everything for dynamic settings" do
    with_env("SMTP_MAX_CONN" => "42") do
      Settings.overrides = { smtp_max_conn: 77 }
      Settings.store = -> { { "smtp_max_conn" => "9" } }
      Settings.refresh!
      assert_equal 9, Settings[:smtp_max_conn]
      assert_equal :db, Settings.provenance(:smtp_max_conn)
      assert_equal 77, Settings.static(:smtp_max_conn)
    end
  end

  test "static settings never take db overrides" do
    Settings.store = -> { { "smtp_port" => "2525" } }
    Settings.refresh!
    assert_equal 1025, Settings[:smtp_port]
  end

  test "an unusable db row is skipped, not fatal" do
    Settings.store = -> { { "smtp_max_conn" => "junk", "smtp_send_quota" => "5" } }
    Settings.refresh!
    assert_equal 100, Settings[:smtp_max_conn]
    assert_equal 5, Settings[:smtp_send_quota]
  end

  test "a store error keeps the last good snapshot" do
    calls = 0
    rows = { "smtp_max_conn" => "9" }
    Settings.store = lambda do
      calls += 1
      raise "db down" if calls > 1

      rows
    end
    Settings.refresh!
    assert_equal 9, Settings[:smtp_max_conn]
    Settings.refresh!
    assert_equal 9, Settings[:smtp_max_conn], "failure must keep the last good snapshot"
  end

  test "refresh applies changes immediately, bypassing the TTL" do
    rows = { "smtp_max_conn" => "9" }
    Settings.store = -> { rows.dup }
    Settings.refresh!
    assert_equal 9, Settings[:smtp_max_conn]
    rows["smtp_max_conn"] = "11"
    Settings.refresh!
    assert_equal 11, Settings[:smtp_max_conn]
    rows.clear
    Settings.refresh!
    assert_equal 100, Settings[:smtp_max_conn], "deleted row falls back to the default"
  end

  # -- serialization ----------------------------------------------------

  test "definitions serialize canonically" do
    assert_equal "1", Settings.definition(:smtp_sender_auth).serialize(true)
    assert_equal "0", Settings.definition(:smtp_sender_auth).serialize(false)
    assert_equal "a.example,b.example", Settings.definition(:smtp_rbl_zones).serialize(%w[a.example b.example])
    assert_equal "42", Settings.definition(:smtp_max_conn).serialize(42)
  end

  test "every dynamic setting round-trips through serialize and coerce" do
    samples = { integer: 7200, boolean: true, string: "log", list: %w[a.example b.example], addr: "host:1234" }
    MailOnRails::Settings.definitions.select(&:dynamic?).each do |defn|
      value = samples.fetch(defn.type)
      value = defn.coerce(defn.serialize(value))
      assert_equal defn.coerce(value), value, "#{defn.name} must round-trip"
    rescue ArgumentError
      # Settings with enum/pattern validators reject the generic sample;
      # round-trip those with their own default instead.
      next if defn.default.nil?

      assert_equal defn.default, defn.coerce(defn.serialize(defn.default)), "#{defn.name} default must round-trip"
    end
  end
end
