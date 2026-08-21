# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/sender_auth"
require "fake_resolver"
# The sealer is a plain-Ruby app model (no Rails dependency): validating
# chains it produced pins the two halves against each other, on top of the
# app suite's independent re-implementation check.
require File.expand_path("../../app/models/mail_on_rails/arc_sealer", __dir__)

class ArcTest < Minitest::Test
  KEY = OpenSSL::PKey::RSA.new(2048)
  SECOND_KEY = OpenSSL::PKey::RSA.new(2048)

  MESSAGE = "From: alice@origin.test\r\n" \
            "To: list@forwarder.test\r\n" \
            "Subject: hello\r\n" \
            "Date: Fri, 07 Aug 2026 12:00:00 +0000\r\n" \
            "Message-ID: <m1@origin.test>\r\n" \
            "\r\n" \
            "line one\r\nline two\r\n"

  AUTH = "forwarder.test; spf=pass smtp.mailfrom=origin.test; dkim=pass header.d=origin.test; dmarc=pass"

  def seal(raw = MESSAGE, domain: "forwarder.test", key: KEY, chain: nil, auth: AUTH)
    MailOnRails::ArcSealer.seal(raw, auth_results: auth, domain: domain, selector: "rail",
                                private_key: key, chain: chain)
  end

  def resolver(records = {})
    FakeResolver.new(txt: {
      "rail._domainkey.forwarder.test" => [ "v=DKIM1; k=rsa; p=#{[ KEY.public_to_der ].pack("m0")}" ],
      "rail._domainkey.second.test" => [ "v=DKIM1; k=rsa; p=#{[ SECOND_KEY.public_to_der ].pack("m0")}" ]
    }.merge(records))
  end

  def evaluate(message, res = resolver)
    MailOnRails::SenderAuth::Arc.new(res).evaluate(message)
  end

  test "a message without ARC headers is none" do
    assert_equal :none, evaluate(MESSAGE)[:result]
  end

  test "an intact instance-1 chain passes and names its sealer" do
    verdict = evaluate(seal)
    assert_equal :pass, verdict[:result], verdict.inspect
    assert_equal "forwarder.test", verdict[:sealer]
    assert_equal [ "forwarder.test" ], verdict[:sealers]
  end

  test "an extended chain (cv=pass at i=2) passes and names the newest sealer" do
    extended = seal(seal, domain: "second.test", key: SECOND_KEY, chain: :pass,
                    auth: "second.test; arc=pass; dmarc=fail")
    verdict = evaluate(extended)
    assert_equal :pass, verdict[:result], verdict.inspect
    assert_equal "second.test", verdict[:sealer]
    assert_equal %w[forwarder.test second.test], verdict[:sealers]
  end

  test "a tampered body fails the newest AMS" do
    verdict = evaluate(seal.sub("line one", "evil one"))
    assert_equal :fail, verdict[:result]
    assert_match(/ARC-Message-Signature/, verdict[:detail])
  end

  test "a tampered older seal fails the chain" do
    extended = seal(seal, domain: "second.test", key: SECOND_KEY, chain: :pass)
    # Corrupt the i=1 seal's b= value without touching structure.
    tampered = extended.sub(/^(ARC-Seal: i=1;[^\r]*b=)([A-Za-z0-9+\/]{4})/, '\1AAAA')
    verdict = evaluate(tampered)
    assert_equal :fail, verdict[:result], verdict.inspect
  end

  test "a chain sealed over a failed chain (cv=fail) never passes" do
    over_failure = seal(seal, domain: "second.test", key: SECOND_KEY, chain: :fail)
    verdict = evaluate(over_failure)
    assert_equal :fail, verdict[:result]
    assert_match(/cv=fail/, verdict[:detail])
  end

  test "cv=none above instance 1 is dishonest and fails" do
    extended = seal(seal, domain: "second.test", key: SECOND_KEY, chain: :pass)
    forged = extended.sub("ARC-Seal: i=2; a=rsa-sha256; cv=pass", "ARC-Seal: i=2; a=rsa-sha256; cv=none")
    assert_equal :fail, evaluate(forged)[:result]
  end

  test "an incomplete set is permerror" do
    headerless = seal.sub(/^ARC-Authentication-Results:[^\r]*\r\n/, "")
    verdict = evaluate(headerless)
    assert_equal :permerror, verdict[:result]
  end

  test "a transient DNS failure is temperror" do
    res = resolver("rail._domainkey.forwarder.test" => :temperror)
    assert_equal :temperror, evaluate(seal, res)[:result]
  end

  test "a missing key record fails rather than passing" do
    res = FakeResolver.new(txt: {})
    assert_equal :fail, evaluate(seal, res)[:result]
  end

  # -- sealer chain-extension guardrails --------------------------------------

  test "the sealer leaves an existing chain untouched without a verdict" do
    once = seal
    assert_equal once, seal(once)
  end

  test "the sealer refuses to extend past the chain cap" do
    message = seal
    (2..MailOnRails::ArcSealer::MAX_CHAIN).each { message = seal(message, chain: :pass) }
    assert_equal message, seal(message, chain: :pass),
                 "instance #{MailOnRails::ArcSealer::MAX_CHAIN + 1} must not be created"
  end

  test "sender_auth verify carries the arc verdict into the summary" do
    result = MailOnRails::SenderAuth::Result.new(
      spf: { result: :fail, domain: "origin.test" }, dkim: [],
      dmarc: { result: :fail, policy: :reject, from_domain: "origin.test" },
      arc: { result: :pass, sealer: "forwarder.test", sealers: [ "forwarder.test" ] }
    )
    assert_includes result.summary, "arc=pass arc.d=forwarder.test"
    assert result.dmarc_reject?
  end

  test "arc_trusted_pass? honors the smtp_arc_trusted_sealers setting" do
    result = MailOnRails::SenderAuth::Result.new(
      spf: { result: :fail }, dkim: [], dmarc: { result: :fail, policy: :reject },
      arc: { result: :pass, sealer: "forwarder.test", sealers: [ "forwarder.test" ] }
    )
    refute result.arc_trusted_pass?, "no sealers are trusted by default"

    MailOnRails::Settings.overrides = { smtp_arc_trusted_sealers: [ "Forwarder.TEST" ] }
    assert result.arc_trusted_pass?, "the listed sealer must match case-insensitively"

    failed = MailOnRails::SenderAuth::Result.new(
      spf: { result: :fail }, dkim: [], dmarc: { result: :fail, policy: :reject },
      arc: { result: :fail, sealer: "forwarder.test", sealers: [ "forwarder.test" ] }
    )
    refute failed.arc_trusted_pass?, "only an intact chain can override"
  ensure
    MailOnRails::Settings.reset!
  end
end
