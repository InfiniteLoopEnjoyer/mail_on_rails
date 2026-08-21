# frozen_string_literal: true

require_relative "test_helper"

# Security bounds on admin-tunable knobs: the auth throttle cannot be
# weakened to nothing, and the scanner addresses - writable from the
# settings UI at runtime - cannot be steered into link-local/metadata
# address space or arbitrary URL schemes.
class HardeningTest < Minitest::Test
  Settings = MailOnRails::Settings

  THROTTLE_KNOBS = {
    auth_max_ip_failures: "MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES",
    auth_max_account_failures: "MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES",
    auth_ip_block: "MAIL_ON_RAILS_AUTH_IP_BLOCK",
    auth_account_block: "MAIL_ON_RAILS_AUTH_ACCOUNT_BLOCK"
  }.freeze

  def teardown
    Settings.reset!
  end

  test "auth throttle knobs cannot be weakened to zero from env" do
    THROTTLE_KNOBS.each do |name, env|
      with_env(env => "0") do
        assert_raises(MailOnRails::Netserv::Config::Error, "#{env}=0 must be rejected") do
          Settings[name]
        end
      end
      with_env(env => "1") do
        assert_equal 1, Settings[name]
      end
    end
  end

  test "auth throttle knobs cannot be weakened to zero from the settings ui" do
    THROTTLE_KNOBS.each_key do |name|
      definition = Settings.definition(name)

      assert_raises(ArgumentError, "#{name}=0 must be rejected") { definition.coerce("0") }
      assert_equal 1, definition.coerce("1")
    end
  end

  test "scanner addresses accept the normal deployment shapes" do
    clamav = Settings.definition(:smtp_clamav_addr)
    rspamd = Settings.definition(:smtp_rspamd_addr)

    assert_equal "", clamav.coerce(""), "empty disables the scanner"
    assert_equal "clamav:3310", clamav.coerce("clamav:3310")
    assert_equal "127.0.0.1:3310", clamav.coerce("127.0.0.1:3310")
    assert_equal "rspamd:11334", rspamd.coerce("rspamd:11334")
    assert_equal "http://rspamd:11334", rspamd.coerce("http://rspamd:11334")
    assert_equal "https://rspamd.internal:11334", rspamd.coerce("https://rspamd.internal:11334")
  end

  test "scanner addresses reject SSRF shapes" do
    clamav = Settings.definition(:smtp_clamav_addr)
    rspamd = Settings.definition(:smtp_rspamd_addr)

    [ "169.254.169.254:80", "169.254.10.1:3310", "clamav:99999", "clamav:0",
      "http://clamav:3310", "bad host:3310", ":3310" ].each do |addr|
      assert_raises(ArgumentError, "clamav addr #{addr.inspect} must be rejected") do
        clamav.coerce(addr)
      end
    end

    [ "http://169.254.169.254/latest/meta-data", "https://169.254.169.254",
      "gopher://internal:70", "file:///etc/passwd", "http://user@host:11334" ].each do |addr|
      assert_raises(ArgumentError, "rspamd addr #{addr.inspect} must be rejected") do
        rspamd.coerce(addr)
      end
    end
  end

  # Hand-rolled singleton stub (minitest/mock isn't bundled): pin what the
  # hostname resolves to, so the rebinding check is deterministic.
  def with_resolved_addresses(addresses)
    singleton = Resolv.singleton_class
    original = Resolv.method(:getaddresses)
    singleton.define_method(:getaddresses) { |_host| addresses }
    yield
  ensure
    singleton.define_method(:getaddresses, original)
  end

  test "a hostname resolving into link-local/metadata space is rejected like the literal" do
    clamav = Settings.definition(:smtp_clamav_addr)
    rspamd = Settings.definition(:smtp_rspamd_addr)

    with_resolved_addresses([ "169.254.169.254" ]) do
      assert_raises(ArgumentError) { clamav.coerce("metadata.internal:3310") }
      assert_raises(ArgumentError) { rspamd.coerce("http://metadata.internal:11334") }
    end
  end

  test "an unresolvable hostname still validates (the accessory may not be up yet)" do
    clamav = Settings.definition(:smtp_clamav_addr)

    with_resolved_addresses([]) do
      assert_equal "clamav:3310", clamav.coerce("clamav:3310")
    end
  end

  test "smarthost tls mode accepts only the three transports" do
    definition = Settings.definition(:smarthost_tls)

    %w[opportunistic starttls smtps].each { |mode| assert_equal mode, definition.coerce(mode) }
    assert_raises(ArgumentError) { definition.coerce("plaintext") }
  end
end
