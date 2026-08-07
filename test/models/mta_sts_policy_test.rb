require "test_helper"

# The MTA-STS sending side (RFC 8461): TXT discovery, HTTPS policy
# parsing, the DB cache that keeps a policy in force for max_age, and MX
# pattern matching.
class MtaStsPolicyTest < ActiveSupport::TestCase
  # Hash-backed stand-in for the SenderAuth Dns client (same seam the
  # verifier tests use); TempError-on-demand via :temperror.
  class FakeDns
    def initialize(txt = {})
      @txt = txt
    end

    def txt(name)
      value = @txt.fetch(name, [])
      raise MailOnRails::Smtp::SenderAuth::Dns::TempError, "boom" if value == :temperror

      value
    end
  end

  VALID_BODY = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.backup.example.com\nmax_age: 86400\n".freeze

  def with_policy_body(result)
    singleton = MtaStsPolicy.singleton_class
    original = MtaStsPolicy.method(:fetch_policy_body)
    singleton.define_method(:fetch_policy_body) do |_domain|
      raise MtaStsPolicy::FetchError, "unreachable" if result == :error

      result
    end
    yield
  ensure
    singleton.define_method(:fetch_policy_body, original)
  end

  def sts_txt(id) = { "_mta-sts.example.com" => [ "v=STSv1; id=#{id}" ] }

  test "parse reads a policy and rejects garbage" do
    fields = MtaStsPolicy.parse(VALID_BODY)
    assert_equal "enforce", fields[:mode]
    assert_equal 86_400, fields[:max_age]
    assert_equal [ "mx1.example.com", "*.backup.example.com" ], fields[:mx]

    assert_raises(MtaStsPolicy::FetchError) { MtaStsPolicy.parse("version: STSv2\nmode: enforce\nmax_age: 1") }
    assert_raises(MtaStsPolicy::FetchError) { MtaStsPolicy.parse("version: STSv1\nmode: sideways\nmax_age: 1") }
    assert_raises(MtaStsPolicy::FetchError) { MtaStsPolicy.parse("version: STSv1\nmode: enforce\nmax_age: 0\nmx: a") }
    assert_raises(MtaStsPolicy::FetchError) { MtaStsPolicy.parse("version: STSv1\nmode: enforce\nmax_age: 60") }
  end

  test "a first lookup fetches and caches the policy" do
    lookup = with_policy_body(VALID_BODY) do
      MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123")))
    end

    assert lookup.policy.enforce?
    assert_not lookup.fetch_error
    assert_equal "abc123", MtaStsPolicy.find_by(domain: "example.com").sts_id
  end

  test "an unchanged id is served from cache without fetching" do
    with_policy_body(VALID_BODY) { MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123"))) }

    lookup = with_policy_body(:error) do
      MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123")))
    end
    assert lookup.policy.enforce?, "cache must serve without a fetch"
    assert_not lookup.fetch_error
  end

  test "a changed id refetches" do
    with_policy_body(VALID_BODY) { MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123"))) }

    body = VALID_BODY.sub("enforce", "testing")
    lookup = with_policy_body(body) do
      MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("def456")))
    end
    assert_equal "testing", lookup.policy.mode
    assert_equal "def456", lookup.policy.sts_id
  end

  test "a failed refetch keeps the valid cached policy but flags the fetch error" do
    with_policy_body(VALID_BODY) { MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123"))) }

    lookup = with_policy_body(:error) do
      MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("def456")))
    end
    assert lookup.policy.enforce?, "RFC 8461: the cached policy stays in force"
    assert lookup.fetch_error
  end

  test "a vanished TXT record does not drop a still-valid cached policy" do
    with_policy_body(VALID_BODY) { MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123"))) }

    lookup = MtaStsPolicy.lookup("example.com", dns: FakeDns.new)
    assert lookup.policy.enforce?, "a DNS-blocking attacker must not downgrade a known domain"
  end

  test "an expired cache with no reachable policy yields none" do
    with_policy_body(VALID_BODY) { MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123"))) }

    travel(2.days) do
      lookup = with_policy_body(:error) do
        MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123")))
      end
      assert_nil lookup.policy
      assert lookup.fetch_error
    end
  end

  test "resolver trouble serves the cache and flags nothing" do
    with_policy_body(VALID_BODY) { MtaStsPolicy.lookup("example.com", dns: FakeDns.new(sts_txt("abc123"))) }

    lookup = MtaStsPolicy.lookup("example.com", dns: FakeDns.new("_mta-sts.example.com" => :temperror))
    assert lookup.policy.enforce?
    assert_not lookup.fetch_error
  end

  test "multiple STSv1 TXT records read as no policy advertised" do
    dns = FakeDns.new("_mta-sts.example.com" => [ "v=STSv1; id=a", "v=STSv1; id=b" ])
    assert_nil MtaStsPolicy.lookup("example.com", dns: dns).policy
  end

  test "mx_match? does exact and single-label wildcard matching" do
    policy = MtaStsPolicy.new(mx_patterns: [ "mx1.example.com", "*.backup.example.com" ])

    assert policy.mx_match?("mx1.example.com")
    assert policy.mx_match?("MX1.EXAMPLE.COM.")
    assert policy.mx_match?("a.backup.example.com")
    assert_not policy.mx_match?("backup.example.com"), "wildcard needs exactly one extra label"
    assert_not policy.mx_match?("a.b.backup.example.com"), "wildcard matches only one label"
    assert_not policy.mx_match?("evil.com")
  end
end
