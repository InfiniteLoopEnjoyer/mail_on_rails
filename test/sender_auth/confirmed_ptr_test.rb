# frozen_string_literal: true

require "test_helper"
require "fake_resolver"
require "mail_on_rails/sender_auth/confirmed_ptr"

# SenderAuth::ConfirmedPtr: only PTR names that resolve back to the address
# count, and a resolver failure is an error rather than "no name" - the
# caller is deciding on a permanent ban.
class ConfirmedPtrTest < Minitest::Test
  TempError = MailOnRails::SenderAuth::Dns::TempError

  # The shared hash-backed resolver, counting forward lookups.
  class CountingResolver < FakeResolver
    attr_reader :forward_lookups

    def a(name) = count { super }
    def aaaa(name) = count { super }

    private

    def count
      @forward_lookups = forward_lookups.to_i + 1
      yield
    end
  end

  def names(ip, **records) = MailOnRails::SenderAuth::ConfirmedPtr.names(ip, resolver: FakeResolver.new(records))

  test "a name that resolves back is confirmed, lowercased, without the trailing dot" do
    assert_equal [ "mail-a.google.com" ],
                 names("203.0.113.9", ptr: { "203.0.113.9" => [ "Mail-A.Google.com." ] },
                                      a: { "mail-a.google.com" => [ "198.51.100.1", "203.0.113.9" ] })
  end

  test "a name that resolves elsewhere, or nowhere, is only a claim" do
    assert_empty names("203.0.113.9", ptr: { "203.0.113.9" => [ "mail.google.com", "gone.example" ] },
                                      a: { "mail.google.com" => [ "198.51.100.1" ] })
  end

  test "no PTR, no names" do
    assert_empty names("203.0.113.9")
  end

  test "IPv6 confirms through AAAA, whatever the spelling" do
    assert_equal [ "mx.example.test" ],
                 names("2001:db8::25", ptr: { "2001:db8::25" => [ "mx.example.test" ] },
                                       aaaa: { "mx.example.test" => [ "2001:0db8:0:0:0:0:0:0025" ] })
  end

  test "a v4-mapped peer is looked up as the IPv4 address it is" do
    assert_equal [ "mx.example.test" ],
                 names("::ffff:203.0.113.9", ptr: { "203.0.113.9" => [ "mx.example.test" ] },
                                             a: { "mx.example.test" => [ "203.0.113.9" ] })
  end

  test "a failed PTR lookup raises" do
    assert_raises(TempError) { names("203.0.113.9", ptr: { "203.0.113.9" => :temperror }) }
  end

  test "a failed forward lookup raises when nothing else confirmed" do
    assert_raises(TempError) do
      names("203.0.113.9", ptr: { "203.0.113.9" => [ "mail.google.com" ] }, a: { "mail.google.com" => :temperror })
    end
  end

  test "a failed forward lookup does not mask a name that did confirm" do
    assert_equal [ "b.example.test" ],
                 names("203.0.113.9", ptr: { "203.0.113.9" => [ "a.example.test", "b.example.test" ] },
                                      a: { "a.example.test" => :temperror, "b.example.test" => [ "203.0.113.9" ] })
  end

  test "an oversized PTR set costs a bounded number of forward lookups" do
    resolver = CountingResolver.new(ptr: { "203.0.113.9" => (1..40).map { |n| "host#{n}.example.test" } })

    assert_empty MailOnRails::SenderAuth::ConfirmedPtr.names("203.0.113.9", resolver: resolver)
    assert_equal MailOnRails::SenderAuth::ConfirmedPtr::MAX_NAMES, resolver.forward_lookups
  end

  test "a non-address has no names" do
    assert_empty names("mail.example.test")
    assert_empty names(nil)
  end
end
