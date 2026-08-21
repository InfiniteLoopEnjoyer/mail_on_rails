# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/sender_auth/dns"
require "mail_on_rails/dnssec"

# The DANE-facing pair (tlsa/mx_answer) now rides the in-process
# validating resolver (Dnssec::Resolver): Answer#secure is the resolver's
# :secure verdict, :insecure surfaces as secure: false, :bogus and
# transport failures raise TempError so deliveries defer. The resolver is
# injected; its own verification behavior is covered by test/dnssec.
class DnsDnssecTest < Minitest::Test
  Dns = MailOnRails::Smtp::SenderAuth::Dns
  Result = MailOnRails::Dnssec::Resolver::Answer

  TLSA_NAME = "_25._tcp.mx.example.com"

  # Scripted stand-in for Dnssec::Resolver: maps "name|TYPE" to a
  # Resolver::Answer (or a proc, for raising), counting calls.
  class FakeResolver
    attr_reader :calls

    def initialize(answers)
      @answers = answers
      @calls = []
    end

    def resolve(name, type)
      key = "#{name}|#{type}"
      @calls << key
      answer = @answers.fetch(key)
      answer.is_a?(Proc) ? answer.call : answer
    end
  end

  def dns_with(answers, cache_ttl: 60, clock: -> { 0.0 })
    resolver = FakeResolver.new(answers)
    [ Dns.new(nameservers: [ "192.0.2.53" ], resolver: resolver, cache_ttl: cache_ttl, clock: clock), resolver ]
  end

  def tlsa_rr(usage: 3, selector: 1, matching_type: 1, data: "ab" * 32, ttl: 300)
    Dnsruby::RR.create("#{TLSA_NAME}. #{ttl} IN TLSA #{usage} #{selector} #{matching_type} #{data}")
  end

  test "secure TLSA answers parse into usage/selector/matching_type/data" do
    dns, = dns_with({
      "#{TLSA_NAME}|TLSA" => Result.new(status: :secure, records: [
        tlsa_rr,
        tlsa_rr(usage: 2, selector: 0, matching_type: 2, data: "01" * 64)
      ])
    })

    answer = dns.tlsa(TLSA_NAME)
    assert answer.secure
    assert_equal 2, answer.records.size
    first = answer.records.first
    assert_equal [ 3, 1, 1 ], [ first.usage, first.selector, first.matching_type ]
    assert_equal ("\xab".b * 32), first.data
  end

  test "an :insecure answer keeps its records but is not secure" do
    dns, = dns_with({ "#{TLSA_NAME}|TLSA" => Result.new(status: :insecure, records: [ tlsa_rr ]) })

    answer = dns.tlsa(TLSA_NAME)
    refute answer.secure
    assert_equal 1, answer.records.size
  end

  test "a secure denial is an empty secure answer - the no-DANE-published signal" do
    dns, = dns_with({ "#{TLSA_NAME}|TLSA" => Result.new(status: :secure, records: [], proof: :no_data) })

    answer = dns.tlsa(TLSA_NAME)
    assert answer.secure
    assert_empty answer.records
  end

  test ":bogus raises TempError so the delivery defers" do
    dns, = dns_with({
      "#{TLSA_NAME}|TLSA" => Result.new(status: :bogus, records: [], reason: "signature failed")
    })

    error = assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
    assert_match(/signature failed/, error.message)
  end

  test "resolver transport failures surface as TempError" do
    dns, = dns_with({
      "#{TLSA_NAME}|TLSA" => -> { raise MailOnRails::Dnssec::Transport::TempError, "upstream gone" }
    })

    assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
  end

  test "mx_answer sorts by preference and carries the verdict" do
    mx = [
      Dnsruby::RR.create("example.com. 300 IN MX 20 backup.example.com."),
      Dnsruby::RR.create("example.com. 300 IN MX 10 mail.example.com.")
    ]
    dns, = dns_with({ "example.com|MX" => Result.new(status: :secure, records: mx) })

    answer = dns.mx_answer("example.com")
    assert answer.secure
    assert_equal [ [ 10, "mail.example.com" ], [ 20, "backup.example.com" ] ], answer.records
  end

  test "validated answers cache; bogus never does" do
    calls = 0
    flapping = lambda do
      calls += 1
      raise MailOnRails::Dnssec::Transport::TempError, "flap" if calls == 1

      Result.new(status: :secure, records: [ tlsa_rr ])
    end
    dns, resolver = dns_with({ "#{TLSA_NAME}|TLSA" => flapping })

    assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
    assert dns.tlsa(TLSA_NAME).secure, "the failure must not be cached"
    dns.tlsa(TLSA_NAME)
    assert_equal 2, resolver.calls.size, "the validated answer should have cached"
  end

  test "cache expiry honors record TTLs below the cap" do
    now = [ 0.0 ]
    dns, resolver = dns_with(
      { "#{TLSA_NAME}|TLSA" => Result.new(status: :secure, records: [ tlsa_rr(ttl: 5) ]) },
      cache_ttl: 60, clock: -> { now[0] }
    )

    dns.tlsa(TLSA_NAME)
    dns.tlsa(TLSA_NAME)
    assert_equal 1, resolver.calls.size

    now[0] = 6.0
    dns.tlsa(TLSA_NAME)
    assert_equal 2, resolver.calls.size, "the 5s record TTL should bound the 60s cap"
  end

  test "without an injected resolver a real validating resolver is built lazily" do
    dns = Dns.new(nameservers: [ "192.0.2.53" ])
    resolver = dns.send(:dnssec_resolver)
    assert_instance_of MailOnRails::Dnssec::Resolver, resolver
  end
end
