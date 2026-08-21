# frozen_string_literal: true

require "test_helper"
require "fake_resolver"

# CymruLookup parses Team Cymru's DNS answers into ASN/country/rDNS. Driven
# with the hash-backed FakeResolver - no network.
class CymruLookupTest < Minitest::Test
  def lookup(ip, records)
    MailOnRails::CymruLookup.lookup(ip, resolver: FakeResolver.new(records))
  end

  def test_parses_asn_country_prefix_name_and_rdns
    result = lookup("203.0.113.7",
      txt: {
        "7.113.0.203.origin.asn.cymru.com" => [ "13335 | 203.0.113.0/24 | US | arin | 2010-01-01" ],
        "as13335.asn.cymru.com" => [ "13335 | US | arin | 2010-01-01 | CLOUDFLARENET, US" ]
      },
      ptr: { "203.0.113.7" => [ "scanner.evil.test." ] })

    assert_equal "13335", result[:asn]
    assert_equal "US", result[:country]
    assert_equal "203.0.113.0/24", result[:prefix]
    assert_equal "CLOUDFLARENET, US", result[:as_name]
    assert_equal "scanner.evil.test", result[:rdns]
  end

  def test_missing_origin_record_yields_nil_fields
    result = lookup("203.0.113.7", ptr: { "203.0.113.7" => [ "host.test." ] })

    assert_nil result[:asn]
    assert_nil result[:country]
    assert_equal "host.test", result[:rdns]
  end

  def test_a_resolver_error_is_swallowed
    result = lookup("203.0.113.7",
      txt: { "7.113.0.203.origin.asn.cymru.com" => :temperror },
      ptr: { "203.0.113.7" => :temperror })

    assert_nil result[:asn]
    assert_nil result[:rdns]
  end

  def test_ipv6_uses_the_origin6_zone
    result = lookup("2001:db8::1",
      txt: {
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com" =>
          [ "64500 | 2001:db8::/32 | NL | ripencc | 2015-01-01" ]
      })

    assert_equal "64500", result[:asn]
    assert_equal "NL", result[:country]
  end
end
