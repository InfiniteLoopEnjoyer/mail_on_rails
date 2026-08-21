# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/ingress_seal"

# The HMAC seal that lets MailroomMailbox prove the trusted routing/auth
# headers came from the SMTP edge and not from some other ingress route.
class IngressSealTest < Minitest::Test
  Seal = MailOnRails::IngressSeal
  KEY = ("k" * 32).b
  OTHER_KEY = ("z" * 32).b

  STAMPED = "Return-Path: <alice@example.com>\r\n" \
            "X-Original-To: bob@example.net\r\n" \
            "X-MailOnRails-Authenticated: no\r\n" \
            "\r\nHello Bob.\r\n"

  def sealed(message = STAMPED, now: 1_000_000)
    Seal.seal(message, now: now, key: KEY) + message
  end

  test "a freshly sealed message verifies" do
    assert Seal.verify(sealed, now: 1_000_010, key: KEY)
  end

  test "the seal header is the first physical line" do
    assert_match(/\AX-MailOnRails-Seal: v1; t=\d+; d=[0-9a-f]+\r\n/, sealed)
  end

  test "an unsealed message does not verify" do
    refute Seal.verify(STAMPED, now: 1_000_000, key: KEY)
  end

  test "tampering with a header breaks the seal" do
    tampered = sealed.sub("bob@example.net", "mallory@example.net")

    refute Seal.verify(tampered, now: 1_000_010, key: KEY)
  end

  test "tampering with the body breaks the seal" do
    tampered = sealed.sub("Hello Bob.", "Hello Eve.")

    refute Seal.verify(tampered, now: 1_000_010, key: KEY)
  end

  test "a seal from a different key does not verify" do
    refute Seal.verify(sealed, now: 1_000_010, key: OTHER_KEY)
  end

  test "an expired seal does not verify" do
    refute Seal.verify(sealed(now: 1), now: 1 + Seal::DEFAULT_MAX_AGE + 1, key: KEY)
  end

  test "a seal from the future beyond tolerance does not verify" do
    refute Seal.verify(sealed(now: 9_000_000), now: 1, key: KEY)
  end

  test "a garbage seal header does not verify or raise" do
    forged = "X-MailOnRails-Seal: v1; t=1000000; d=deadbeef\r\n" + STAMPED

    refute Seal.verify(forged, now: 1_000_000, key: KEY)
  end
end
