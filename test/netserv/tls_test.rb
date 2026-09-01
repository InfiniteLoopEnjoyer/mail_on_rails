# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "mail_on_rails/netserv/tls"

# Operator-supplied TLS material (Netserv::Tls): a private key file other
# users can read earns a warning at boot and on every reload, never a
# refusal - a renewal tool writing 0644 must not take the listener down.
class TlsKeyPermissionsTest < Minitest::Test
  Tls = MailOnRails::Netserv::Tls

  class Recorder
    attr_reader :warnings

    def initialize = @warnings = []
    def warn(message) = @warnings << message
  end

  PEMS = Tls.generate_self_signed([ "localhost" ])

  def setup
    @dir = Dir.mktmpdir("mail_on_rails_tls")
    @cert = File.join(@dir, "cert.pem")
    @key = File.join(@dir, "key.pem")
    File.write(@cert, PEMS[:cert])
    File.write(@key, PEMS[:key])
    @logger = Recorder.new
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  test "a group/world-readable key is reported with its mode and the fix" do
    File.chmod(0o644, @key)
    material = Tls.for(:smtp).explicit_material(@cert, @key, logger: @logger)

    assert_equal({ cert_path: @cert, key_path: @key }, material, "the material is still usable")
    assert_equal 1, @logger.warnings.size
    assert_match(/#{Regexp.escape(@key)}.*group\/world-readable.*0644.*chmod 600/, @logger.warnings.first)
  end

  test "a key readable only by its owner passes silently" do
    File.chmod(0o600, @key)
    Tls.for(:smtp).explicit_material(@cert, @key, logger: @logger)

    assert_empty @logger.warnings
  end

  test "the context provider warns again when a renewal lands with loose permissions" do
    File.chmod(0o600, @key)
    provider = Tls::ContextProvider.new({ cert_path: @cert, key_path: @key }, logger: @logger)
    assert_empty @logger.warnings

    File.chmod(0o640, @key)
    future = Time.now + 60
    File.utime(future, future, @key) # a renewal: new mtime, and this time group-readable
    provider.context

    assert_equal 1, @logger.warnings.size
    assert_match(/0640/, @logger.warnings.first)
  end

  test "no logger means no warning and no error" do
    File.chmod(0o644, @key)
    assert Tls.for(:smtp).explicit_material(@cert, @key)
    assert Tls::ContextProvider.new({ cert_path: @cert, key_path: @key }).context
  end
end
