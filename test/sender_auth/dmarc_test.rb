require "test_helper"
require "mail_on_rails/sender_auth"
require "fake_resolver"

class DmarcTest < Minitest::Test
  def evaluate(records, from_domain: "example.com", spf: nil, dkim: [])
    spf ||= { result: :none, domain: nil }
    MailOnRails::SenderAuth::Dmarc.new(FakeResolver.new(txt: records))
      .evaluate(from_domain: from_domain, spf: spf, dkim: dkim)
  end

  test "aligned dkim pass gives dmarc pass" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      dkim: [ { result: :pass, domain: "example.com" } ]
    )
    assert_equal :pass, result[:result]
    assert_equal :none, result[:policy]
  end

  test "aligned spf pass gives dmarc pass" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      spf: { result: :pass, domain: "mail.example.com" } # relaxed alignment: same org domain
    )
    assert_equal :pass, result[:result]
  end

  test "strict spf alignment rejects a subdomain" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject; aspf=s" ] },
      spf: { result: :pass, domain: "mail.example.com" }
    )
    assert_equal :fail, result[:result]
    assert_equal :reject, result[:policy]
  end

  test "nothing aligned fails with the published policy" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=quarantine" ] },
      spf: { result: :pass, domain: "elsewhere.net" },
      dkim: [ { result: :pass, domain: "elsewhere.net" } ]
    )
    assert_equal :fail, result[:result]
    assert_equal :quarantine, result[:policy]
  end

  test "no record anywhere is none" do
    result = evaluate({})
    assert_equal :none, result[:result]
    assert_equal :none, result[:policy]
  end

  test "subdomain falls back to the org domain record and sp=" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject; sp=quarantine" ] },
      from_domain: "news.example.com"
    )
    assert_equal :fail, result[:result]
    assert_equal :quarantine, result[:policy]
  end

  test "org domain respects common two-label suffixes" do
    assert_equal "example.co.uk", MailOnRails::SenderAuth::Dmarc.org_domain("mail.example.co.uk")
    assert_equal "example.com", MailOnRails::SenderAuth::Dmarc.org_domain("a.b.example.com")
  end

  test "org domain uses the full public suffix list when the gem is loaded" do
    skip "public_suffix not loaded" unless defined?(PublicSuffix)

    # Multi-label suffixes absent from the static fallback table.
    assert_equal "example.pvt.k12.ma.us", MailOnRails::SenderAuth::Dmarc.org_domain("www.example.pvt.k12.ma.us")
    assert_equal "user.github.io", MailOnRails::SenderAuth::Dmarc.org_domain("sub.user.github.io"),
                 "private-section PSL entries count, matching common DMARC implementations"
    # Unlisted TLDs keep the last-two-labels default.
    assert_equal "example.test", MailOnRails::SenderAuth::Dmarc.org_domain("mail.example.test")
  end

  test "evaluation carries per-mechanism alignment and the published policy for aggregate reports" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject; sp=none; adkim=s; pct=50" ] },
      spf: { result: :pass, domain: "mail.example.com" },
      dkim: [ { result: :pass, domain: "elsewhere.net" } ]
    )

    assert result[:spf_aligned]
    refute result[:dkim_aligned], "adkim=s must not align an unrelated signing domain"
    assert_equal({ p: "reject", sp: "none", adkim: "s", aspf: "r", pct: 50 }, result[:published])
  end

  test "missing from domain is permerror" do
    result = evaluate({}, from_domain: nil)
    assert_equal :permerror, result[:result]
    assert_equal :none, result[:policy]
  end

  test "multiple dmarc records count as no record" do
    result = evaluate({ "_dmarc.example.com" => [ "v=DMARC1; p=reject", "v=DMARC1; p=none" ] })
    assert_equal :none, result[:result]
  end

  test "pct=0 downgrades reject to quarantine" do
    result = evaluate({ "_dmarc.example.com" => [ "v=DMARC1; p=reject; pct=0" ] })
    assert_equal :fail, result[:result]
    assert_equal :quarantine, result[:policy]
  end

  test "dns failure is temperror" do
    result = evaluate({ "_dmarc.example.com" => :temperror })
    assert_equal :temperror, result[:result]
  end

  test "aligned spf temperror turns fail into temperror" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      spf: { result: :temperror, domain: "mail.example.com" } # could have aligned
    )
    assert_equal :temperror, result[:result]
    assert_equal :none, result[:policy]
  end

  test "aligned dkim temperror turns fail into temperror" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      dkim: [ { result: :temperror, domain: "example.com" } ]
    )
    assert_equal :temperror, result[:result]
  end

  # A spoofer must not soften p=reject into a deferral by attaching a
  # DKIM signature (or MAIL FROM) under broken DNS for an unrelated
  # domain: a temperror that could not have aligned changes nothing.
  test "unaligned temperror does not soften a reject" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      spf: { result: :temperror, domain: "attacker.net" },
      dkim: [ { result: :temperror, domain: "attacker.net" } ]
    )
    assert_equal :fail, result[:result]
    assert_equal :reject, result[:policy]
  end

  test "aligned temperror is ignored when something else aligned and passed" do
    result = evaluate(
      { "_dmarc.example.com" => [ "v=DMARC1; p=reject" ] },
      spf: { result: :temperror, domain: "example.com" },
      dkim: [ { result: :pass, domain: "example.com" } ]
    )
    assert_equal :pass, result[:result]
  end
end
