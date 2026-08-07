require "test_helper"
require "mail_on_rails/smtp/sender_auth/dns"

class OutboundDelivererTest < ActiveSupport::TestCase
  Answer = MailOnRails::Smtp::SenderAuth::Dns::Answer
  Tlsa = MailOnRails::Smtp::SenderAuth::Dns::Tlsa

  # Hash-backed stand-in for the SenderAuth Dns client; records TLSA
  # lookups so tests can assert DANE stayed quiet on insecure paths.
  class FakeDns
    attr_reader :tlsa_calls

    def initialize(mx: {}, tlsa: {}, txt: {})
      @mx, @tlsa, @txt = mx, tlsa, txt
      @tlsa_calls = []
    end

    def mx_answer(name)
      @mx.fetch(name) { Answer.new(records: [], secure: false) }
    end

    def tlsa(name)
      @tlsa_calls << name
      @tlsa.fetch(name) { Answer.new(records: [], secure: false) }
    end

    def txt(name)
      @txt.fetch(name, [])
    end
  end

  setup do
    @deliverer = OutboundDeliverer.new(dns: FakeDns.new)
  end

  def outbound(mail_from: "user@local.test", from_header: "user@local.test", recipient: "rcpt@remote.test")
    headers = from_header ? "From: #{from_header}\r\n" : ""
    SmtpOutboundMessage.new(mail_from: mail_from, recipient: recipient,
                            data: "#{headers}Subject: hi\r\n\r\nbody\r\n")
  end

  # Swap Rails.logger for a capturing one (minitest/mock isn't bundled -
  # same reason the clamav/rspamd stub helpers are hand-rolled).
  def capture_warnings
    io = StringIO.new
    original = Rails.logger
    Rails.logger = ActiveSupport::Logger.new(io)
    yield
    io.string
  ensure
    Rails.logger = original
  end

  # A deliverer whose network layer is the given block: it receives
  # (host, policy) and its result/raise stands in for the SMTP session.
  def deliverer_with(dns, &network)
    deliverer = OutboundDeliverer.new(dns: dns)
    deliverer.define_singleton_method(:send_via) do |host, _port, _message, policy:, auth: {}|
      network.call(host, policy)
    end
    deliverer
  end

  def secure_mx(host: "mx.remote.test")
    { "remote.test" => Answer.new(records: [ [ 10, host ] ], secure: true) }
  end

  def usable_tlsa(host: "mx.remote.test")
    { "_25._tcp.#{host}" => Answer.new(records: [ Tlsa.new(usage: 3, selector: 1, matching_type: 1, data: "\xab".b * 32) ], secure: true) }
  end

  def enforce_policy!(mx_patterns: [ "mx.remote.test" ])
    MtaStsPolicy.create!(domain: "remote.test", sts_id: "id1", mode: "enforce",
                         max_age: 86_400, mx_patterns: mx_patterns, fetched_at: Time.current)
  end

  # --- DKIM signing (unchanged behavior) ---

  test "signs with the From: header domain's DB key, not the envelope domain" do
    Domain.create!(name: "header.test")
    Domain.create!(name: "envelope.test")
    signed = @deliverer.send(:signed, outbound(mail_from: "user@envelope.test", from_header: "Sender <user@header.test>"))
    assert_match(/^DKIM-Signature:.*d=header\.test;/m, signed)
  end

  test "falls back to the envelope domain when the From header is missing" do
    Domain.create!(name: "envelope.test")
    signed = @deliverer.send(:signed, outbound(mail_from: "user@envelope.test", from_header: nil))
    assert_match(/^DKIM-Signature:.*d=envelope\.test;/m, signed)
  end

  test "goes out unsigned, with a warning, when the domain has no key" do
    raw = outbound(mail_from: "user@nokey.test", from_header: "user@nokey.test")
    warnings = capture_warnings do
      assert_equal raw.data, @deliverer.send(:signed, raw)
    end
    assert_includes warnings, "UNSIGNED"
    assert_includes warnings, "nokey.test"
  end

  # --- MX resolution ---

  test "equal-preference MX records are shuffled, lower preference still first" do
    dns = FakeDns.new(mx: { "example.com" => Answer.new(
      records: [ [ 10, "a.example.com" ], [ 10, "b.example.com" ], [ 20, "backup.example.com" ] ], secure: false) })
    deliverer = OutboundDeliverer.new(dns: dns)
    orders = Set.new
    20.times do
      hosts = deliverer.send(:mx_hosts, "example.com").hosts.map(&:first)
      assert_equal "backup.example.com", hosts.last, "higher preference must sort last"
      orders << hosts.first(2)
    end
    assert_equal 2, orders.size, "both orderings of the tied pair should occur across runs"
  end

  test "null MX is a permanent error, no MX falls back to the domain's A record" do
    null_dns = FakeDns.new(mx: { "example.com" => Answer.new(records: [ [ 0, "" ] ], secure: false) })
    assert_raises(OutboundDeliverer::PermanentError) do
      OutboundDeliverer.new(dns: null_dns).send(:mx_hosts, "example.com")
    end

    resolved = OutboundDeliverer.new(dns: FakeDns.new).send(:mx_hosts, "example.com")
    assert_equal [ [ "example.com", 25 ] ], resolved.hosts
    assert resolved.fallback
  end

  # --- policy selection and TLS-RPT events ---

  test "a secure MX with secure usable TLSA delivers under DANE and records a tlsa success" do
    seen = nil
    dns = FakeDns.new(mx: secure_mx, tlsa: usable_tlsa)
    deliverer = deliverer_with(dns) { |_host, policy| seen = policy; true }

    assert deliverer.deliver(outbound)
    assert_equal :dane, seen.mode
    assert_equal 1, seen.tlsa_records.size

    event = TlsRptEvent.sole
    assert_equal [ "remote.test", "tlsa", "mx.remote.test", nil ],
                 [ event.policy_domain, event.policy_type, event.receiving_mx, event.result_type ]
  end

  test "an insecure MX RRset never even looks up TLSA" do
    dns = FakeDns.new(mx: { "remote.test" => Answer.new(records: [ [ 10, "mx.remote.test" ] ], secure: false) })
    deliverer = deliverer_with(dns) { |_host, policy| assert_equal :opportunistic, policy.mode; true }

    assert deliverer.deliver(outbound)
    assert_empty dns.tlsa_calls
  end

  test "insecure TLSA records mean opportunistic delivery" do
    tlsa = { "_25._tcp.mx.remote.test" => Answer.new(
      records: [ Tlsa.new(usage: 3, selector: 1, matching_type: 1, data: "x" * 32) ], secure: false) }
    deliverer = deliverer_with(FakeDns.new(mx: secure_mx, tlsa: tlsa)) do |_host, policy|
      assert_equal :opportunistic, policy.mode
      true
    end

    assert deliverer.deliver(outbound)
  end

  test "a secure TLSA RRset with only unusable records makes the host undeliverable" do
    tlsa = { "_25._tcp.mx.remote.test" => Answer.new(
      records: [ Tlsa.new(usage: 0, selector: 1, matching_type: 1, data: "x" * 32) ], secure: true) }
    deliverer = deliverer_with(FakeDns.new(mx: secure_mx, tlsa: tlsa)) { |_h, _p| flunk "must not connect" }

    assert_raises(OutboundDeliverer::TransientError) { deliverer.deliver(outbound) }
    assert_equal "tlsa-invalid", TlsRptEvent.sole.result_type
  end

  test "a DANE TLS failure defers, never falls back, and is reported" do
    dns = FakeDns.new(mx: secure_mx, tlsa: usable_tlsa)
    deliverer = deliverer_with(dns) { |_h, _p| raise OpenSSL::SSL::SSLError, "DANE verification failed" }

    assert_raises(OutboundDeliverer::TransientError) { deliverer.deliver(outbound) }
    event = TlsRptEvent.sole
    assert_equal [ "tlsa", "validation-failure" ], [ event.policy_type, event.result_type ]
    assert_includes event.failure_detail, "DANE verification failed"
  end

  test "MTA-STS enforce delivers only to policy-matched MX hosts" do
    enforce_policy!
    mx = { "remote.test" => Answer.new(
      records: [ [ 5, "evil.interceptor.test" ], [ 10, "mx.remote.test" ] ], secure: false) }
    tried = []
    deliverer = deliverer_with(FakeDns.new(mx: mx)) do |host, policy|
      tried << [ host, policy.mode ]
      true
    end

    assert deliverer.deliver(outbound)
    assert_equal [ [ "mx.remote.test", :sts_enforce ] ], tried
    assert_equal [ "sts", nil ], [ TlsRptEvent.sole.policy_type, TlsRptEvent.sole.result_type ]
  end

  test "MTA-STS enforce with no matching MX defers and reports" do
    enforce_policy!(mx_patterns: [ "other.remote.test" ])
    deliverer = deliverer_with(FakeDns.new(mx: secure_mx)) { |_h, _p| flunk "must not connect" }

    assert_raises(OutboundDeliverer::TransientError) { deliverer.deliver(outbound) }
    event = TlsRptEvent.sole
    assert_equal [ "sts", "validation-failure" ], [ event.policy_type, event.result_type ]
  end

  test "a testing-mode policy observes but does not filter" do
    enforce_policy!(mx_patterns: [ "other.remote.test" ]).update!(mode: "testing")
    deliverer = deliverer_with(FakeDns.new(mx: secure_mx)) do |_host, policy|
      assert_equal :opportunistic, policy.mode
      true
    end

    assert deliverer.deliver(outbound)
    assert_equal [ "sts", nil ], [ TlsRptEvent.sole.policy_type, TlsRptEvent.sole.result_type ]
  end

  test "DANE takes precedence over MTA-STS for a host under both" do
    enforce_policy!
    deliverer = deliverer_with(FakeDns.new(mx: secure_mx, tlsa: usable_tlsa)) do |_host, policy|
      assert_equal :dane, policy.mode
      true
    end

    assert deliverer.deliver(outbound)
    assert_equal %w[sts tlsa], TlsRptEvent.pluck(:policy_type).sort, "success counts under both policies"
  end

  test "a server refusing STARTTLS under a TLS-requiring policy reports starttls-not-supported" do
    enforce_policy!
    fake_smtp = Object.new
    def fake_smtp.open_timeout=(_v); end
    def fake_smtp.read_timeout=(_v); end
    def fake_smtp.start(**) = raise(Net::SMTPUnsupportedCommand, "STARTTLS is not supported on this server")

    deliverer = OutboundDeliverer.new(dns: FakeDns.new(mx: secure_mx))
    deliverer.define_singleton_method(:build_smtp) { |_h, _p, _policy| fake_smtp }

    assert_raises(OutboundDeliverer::TransientError) { deliverer.deliver(outbound) }
    event = TlsRptEvent.sole
    assert_equal "starttls-not-supported", event.result_type
  end

  test "build_smtp wires the right client per policy mode" do
    dane = @deliverer.send(:build_smtp, "mx.remote.test", 25,
                           OutboundDeliverer::HostPolicy.new(mode: :dane, tlsa_records: [ :r ]))
    assert_instance_of OutboundDeliverer::DaneSmtp, dane
    assert_equal [ :r ], dane.dane_records
    assert_equal "mx.remote.test", dane.dane_hostname

    sts = @deliverer.send(:build_smtp, "mx.remote.test", 25,
                          OutboundDeliverer::HostPolicy.new(mode: :sts_enforce))
    assert_instance_of Net::SMTP, sts

    plain = @deliverer.send(:build_smtp, "mx.remote.test", 25,
                            OutboundDeliverer::HostPolicy.new(mode: :opportunistic))
    assert_instance_of Net::SMTP, plain
  end
end
