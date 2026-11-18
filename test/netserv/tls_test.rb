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

# The listener context's resumption posture: no stateless tickets under a
# never-rotated key; resumption runs through the server-side session cache.
class TlsContextOptionsTest < Minitest::Test
  Tls = MailOnRails::Netserv::Tls

  test "session tickets are off and the session cache is on" do
    ctx = Tls.context(Tls.generate_self_signed([ "localhost" ]))

    assert_equal OpenSSL::SSL::OP_NO_TICKET, ctx.options & OpenSSL::SSL::OP_NO_TICKET
    assert_equal OpenSSL::SSL::OP_NO_RENEGOTIATION, ctx.options & OpenSSL::SSL::OP_NO_RENEGOTIATION
    assert_equal OpenSSL::SSL::SSLContext::SESSION_CACHE_SERVER,
                 ctx.session_cache_mode & OpenSSL::SSL::SSLContext::SESSION_CACHE_SERVER
    assert_equal "mail_on_rails", ctx.session_id_context
  end
end

# The development self-signed key (Netserv::Tls#material without explicit
# paths): created owner-only from its first byte, never write-then-chmod.
class TlsSelfSignedKeyTest < Minitest::Test
  Tls = MailOnRails::Netserv::Tls

  def setup
    @dir = Dir.mktmpdir("mail_on_rails_tls")
    @umask = File.umask(0o022)
  end

  def teardown
    File.umask(@umask)
    FileUtils.remove_entry(@dir)
  end

  def generate = Tls.for(:smtp).send(:load_or_generate_self_signed, @dir, nil)

  def key_file = File.join(@dir, "selfsigned.key")

  test "the generated key is owner-only and loads back" do
    pems = generate

    assert_equal 0o600, File.stat(key_file).mode & 0o777
    assert_equal pems[:key], File.read(key_file)
    assert_equal pems, generate, "the second boot reads the cached pair"
    assert_equal %w[selfsigned.crt selfsigned.key], Dir.children(@dir).sort, "no temporary file is left behind"
  end

  # The window the old write-then-chmod left open: a process that dies
  # (or a chmod that fails) after the write leaves the key at the umask's
  # mode. Nothing may depend on a chmod coming afterwards.
  test "the key is never on disk with a wider mode, even if no chmod ever runs" do
    singleton = File.singleton_class
    original = File.method(:chmod)
    singleton.define_method(:chmod) { |*| raise Errno::EPERM, "chmod" }
    begin
      generate
    rescue Errno::EPERM
      nil
    ensure
      singleton.define_method(:chmod, original)
    end

    Dir.children(@dir).grep(/key/).each do |name|
      assert_equal 0o600, File.stat(File.join(@dir, name)).mode & 0o777, name
    end
    assert File.exist?(key_file)
  end

  test "a key file left behind with loose permissions is replaced, not written through" do
    File.write(key_file, "stale")
    File.chmod(0o644, key_file)

    pems = generate

    assert_equal 0o600, File.stat(key_file).mode & 0o777
    assert_equal pems[:key], File.read(key_file)
  end
end
