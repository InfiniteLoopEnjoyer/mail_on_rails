# frozen_string_literal: true

require_relative "test_helper"
require "fake_resolver"

# What the deliverer makes of the TLSA answer for an MX host. A record
# with malformed association data (a mistyped digest) is an unusable
# record like any other (RFC 7671 section 4.1): beside a good one the
# host keeps its DANE, alone it makes the host undeliverable rather than
# opportunistic - and at no point is it an exception. A lookup that
# fails outright defers on that host and nothing more.
class OutboundDanePolicyTest < DbSuite::TestCase
  Dns = MailOnRails::SenderAuth::Dns
  Deliverer = MailOnRails::OutboundDeliverer

  GOOD = Dns::Tlsa.new(usage: 3, selector: 1, matching_type: 1, data: "\xab".b * 32)
  MISTYPED = Dns::Tlsa.new(usage: 3, selector: 1, matching_type: 1, data: "\xde\xad\xbe\xef".b)

  # FakeResolver plus the DANE-side pair, with a secure MX RRset so the
  # host is DANE-eligible; +tlsa+ is the answer (or a proc that raises).
  class Resolver < FakeResolver
    def initialize(tlsa:)
      super(a: { "mx.dest.test" => [ "93.184.216.34" ] })
      @tlsa = tlsa
    end

    def mx_answer(_name) = Dns::Answer.new(records: [ [ 10, "mx.dest.test" ] ], secure: true)
    def tlsa(_name) = @tlsa.respond_to?(:call) ? @tlsa.call : @tlsa
  end

  def teardown
    MailOnRails::Settings.reset!
  end

  def queued_message
    MailOnRails::SmtpOutboundMessage.create!(mail_from: "user@example.test", recipient: "rcpt@dest.test",
                                             data: "From: user@example.test\r\n\r\nhi",
                                             next_attempt_at: Time.current)
  end

  # A deliverer whose send_via records the policy it was handed.
  def deliverer(tlsa:)
    MailOnRails::Settings.overrides = { mta_sts: false }
    seen = []
    deliverer = Deliverer.new(dns: Resolver.new(tlsa: tlsa))
    deliverer.define_singleton_method(:send_via) do |_host, _port, _message, policy:, **|
      seen << policy
      :delivered
    end
    [ deliverer, seen ]
  end

  test "a mistyped TLSA record beside a good one: DANE with the good one" do
    deliverer, seen = deliverer(tlsa: Dns::Answer.new(records: [ MISTYPED, GOOD ], secure: true))

    assert_equal :delivered, deliverer.deliver(queued_message)
    assert_equal [ :dane ], seen.map(&:mode)
    assert_equal [ GOOD ], seen.first.tlsa_records
  end

  test "nothing but mistyped TLSA records: the host is undeliverable, not opportunistic" do
    deliverer, seen = deliverer(tlsa: Dns::Answer.new(records: [ MISTYPED ], secure: true))

    error = assert_raises(Deliverer::TransientError) { deliverer.deliver(queued_message) }
    assert_match(/mx\.dest\.test: secure TLSA RRset for mx\.dest\.test contains no usable records/, error.message)
    assert_empty seen, "no connection may be attempted without a usable association"
    assert_equal [ "tlsa-invalid" ], MailOnRails::TlsRptEvent.pluck(:result_type), "and TLS-RPT hears about it"
  end

  test "the same records from an insecure answer mean no DANE at all" do
    deliverer, seen = deliverer(tlsa: Dns::Answer.new(records: [ MISTYPED ], secure: false))

    assert_equal :delivered, deliverer.deliver(queued_message)
    assert_equal [ :opportunistic ], seen.map(&:mode)
  end

  test "a TLSA lookup that fails defers on that host" do
    deliverer, seen = deliverer(tlsa: -> { raise Dns::TempError, "DNSSEC lookup failed: ArgumentError: data with invalid value" })

    error = assert_raises(Deliverer::TransientError) { deliverer.deliver(queued_message) }
    assert_match(/mx\.dest\.test: TLSA lookup failed/, error.message)
    assert_empty seen
  end
end
