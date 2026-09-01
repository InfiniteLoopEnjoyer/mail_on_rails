# frozen_string_literal: true

require_relative "test_helper"
require "fake_resolver"

# Outbound MX targets are vetted before the delivery worker connects
# anywhere: each MX host is resolved, non-routable addresses
# (Netserv::NON_ROUTABLE - private, loopback, link-local, CGNAT, ULA, ...)
# are refused, and the socket goes to the vetted address while TLS and
# DANE keep verifying the MX name. The MX RRset is the recipient's DNS,
# so without this a queued message is a blind port-25 connect into the
# worker's own network.
class OutboundTargetsTest < DbSuite::TestCase
  # FakeResolver plus the two DANE-side lookups deliver needs.
  class Resolver < FakeResolver
    Answer = MailOnRails::SenderAuth::Dns::Answer

    def initialize(records = {}, mx_pairs: [])
      super(records)
      @mx_pairs = mx_pairs
    end

    def mx_answer(_name) = Answer.new(records: @mx_pairs, secure: false)
    def tlsa(_name) = Answer.new(records: [], secure: false)
  end

  def deliverer(records = {}, mx_pairs: [])
    MailOnRails::OutboundDeliverer.new(dns: Resolver.new(records, mx_pairs: mx_pairs))
  end

  def vet(hosts, records)
    deliverer(records).send(:vet_targets, hosts.map { |h| [ h, 25 ] })
  end

  test "routable addresses become targets, A records before AAAA, in MX order" do
    targets, skipped = vet(%w[mx1.example.test mx2.example.test],
                           a: { "mx1.example.test" => [ "93.184.216.34" ], "mx2.example.test" => [ "198.41.0.4" ] },
                           aaaa: { "mx1.example.test" => [ "2606:2800:220:1::1" ] })

    assert_equal [ [ "mx1.example.test", 25, "93.184.216.34" ],
                   [ "mx1.example.test", 25, "2606:2800:220:1::1" ],
                   [ "mx2.example.test", 25, "198.41.0.4" ] ], targets
    assert_empty skipped
  end

  test "non-routable addresses are dropped and a host with none left is skipped with a reason" do
    targets, skipped = vet(%w[mx.example.test evil.example.test],
                           a: { "mx.example.test" => [ "10.0.0.5", "93.184.216.34" ],
                                "evil.example.test" => [ "169.254.169.254", "127.0.0.1", "100.64.0.1" ] },
                           aaaa: { "mx.example.test" => [ "fd00:1234:5678::5" ], # a container-network-style ULA
                                   "evil.example.test" => [ "fe80::1", "::1" ] })

    assert_equal [ [ "mx.example.test", 25, "93.184.216.34" ] ], targets
    assert_equal 1, skipped.size
    assert_match(/evil\.example\.test: resolves only to non-routable addresses.*169\.254\.169\.254.*refused/, skipped.first)
  end

  test "a host with no address records or a failing lookup is skipped, not fatal" do
    targets, skipped = vet(%w[nowhere.example.test broken.example.test ok.example.test],
                           a: { "broken.example.test" => :temperror, "ok.example.test" => [ "93.184.216.34" ] })

    assert_equal [ [ "ok.example.test", 25, "93.184.216.34" ] ], targets
    assert_equal 2, skipped.size
    assert_match(/nowhere\.example\.test: no address records/, skipped[0])
    assert_match(/broken\.example\.test: address lookup failed/, skipped[1])
  end

  test "addresses per host are capped" do
    many = Array.new(10) { |i| "93.184.216.#{i + 1}" }
    targets, = vet(%w[mx.example.test], a: { "mx.example.test" => many })

    assert_equal MailOnRails::OutboundDeliverer::MAX_ADDRESSES_PER_HOST, targets.size
    assert_equal many.first(MailOnRails::OutboundDeliverer::MAX_ADDRESSES_PER_HOST), targets.map(&:last)
  end

  test "the socket goes to the vetted address while TLS verifies the MX name" do
    policies = [ :requiretls, :relaxed, :sts_enforce, :opportunistic ].map do |mode|
      MailOnRails::OutboundDeliverer::HostPolicy.new(mode: mode)
    end
    policies << MailOnRails::OutboundDeliverer::HostPolicy.new(mode: :dane, tlsa_records: [])

    policies.each do |policy|
      smtp = deliverer.send(:build_smtp, "mx.example.test", 25, policy, address: "2606:2800:220:1::1")
      assert_equal "2606:2800:220:1::1", smtp.address, "#{policy.mode}: connect to the vetted address"
      assert_equal "mx.example.test", smtp.tls_hostname, "#{policy.mode}: verify the MX name" unless policy.mode == :relaxed
      assert_equal "mx.example.test", smtp.dane_hostname if policy.mode == :dane
    end
  end

  test "the smarthost is connected by name, unvetted" do
    smtp = deliverer.send(:build_smtp, "relay.internal", 587,
                          MailOnRails::OutboundDeliverer::HostPolicy.new(mode: :smarthost_starttls))
    assert_equal "relay.internal", smtp.address
    assert_equal "relay.internal", smtp.tls_hostname
  end

  test "a domain whose every MX is non-routable defers with the refusal named, connecting nowhere" do
    message = MailOnRails::SmtpOutboundMessage.create!(mail_from: "user@example.test", recipient: "victim@target.test",
                                                       data: "From: user@example.test\r\n\r\nhi",
                                                       next_attempt_at: Time.current)
    resolver = Resolver.new({ a: { "mx.target.test" => [ "10.0.0.25" ] }, aaaa: { "mx.target.test" => [ "fd00::25" ] } },
                            mx_pairs: [ [ 10, "mx.target.test" ] ])
    deliverer = MailOnRails::OutboundDeliverer.new(dns: resolver)
    deliverer.define_singleton_method(:send_via) { |*_args, **_opts| flunk "send_via must not run for a non-routable MX" }

    error = assert_raises(MailOnRails::OutboundDeliverer::TransientError) { deliverer.deliver(message) }
    assert_match(/mx\.target\.test: resolves only to non-routable addresses \(10\.0\.0\.25, fd00::25\)/, error.message)
  end
end
