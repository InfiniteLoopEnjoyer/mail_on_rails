# frozen_string_literal: true

require "test_helper"
require "securerandom"

# The transport sends dnsruby-built queries, so their message ids must be
# unpredictable to an off-path attacker (RFC 5452 section 4.4). dnsruby
# 2.0 draws them from SecureRandom itself (1.74 used Kernel#rand and
# needed a patch here); this pins the property we depend on.
class SecureIdTest < Minitest::Test
  def with_fixed_random_number(value)
    original = SecureRandom.method(:random_number)
    SecureRandom.define_singleton_method(:random_number) { |*_args| value }
    yield
  ensure
    SecureRandom.define_singleton_method(:random_number, original)
  end

  test "a fresh header takes its id from SecureRandom" do
    with_fixed_random_number(0x1234) do
      assert_equal 0x1234, Dnsruby::Header.new.id
      assert_equal 0x1234, Dnsruby::Message.new("example.test.", "A").header.id
    end
  end

  test "decoding a wire header keeps the id on the wire" do
    msg = Dnsruby::Message.new("example.test.", "A")
    msg.header.id = 0x4242
    with_fixed_random_number(0x1234) do
      assert_equal 0x4242, Dnsruby::Message.decode(msg.encode).header.id
    end
  end

  test "ids stay inside the 16-bit field" do
    ids = Array.new(200) { Dnsruby::Header.new.id }
    assert ids.all? { |id| (0...Dnsruby::Header::MAX_ID).cover?(id) }
    assert_operator ids.uniq.size, :>, 1
  end
end
