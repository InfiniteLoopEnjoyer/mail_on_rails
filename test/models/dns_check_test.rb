require "test_helper"

class DnsCheckTest < ActiveSupport::TestCase
  # Canned resolver: txt/mx answers keyed by lookup name; nil simulates a
  # DNS failure for that name.
  FakeResolver = Struct.new(:txt_answers, :mx_answers) do
    def txt(name) = txt_answers.fetch(name, [])
    def mx(name) = mx_answers.fetch(name, [])
  end

  setup do
    ENV["SMTP_HELO_HOST"] = "mail.host.test"
    @domain = Domain.create!(name: "example.com")
  end

  teardown do
    ENV.delete("SMTP_HELO_HOST")
  end

  def run_checks(txt: {}, mx: {})
    DnsCheck.for(@domain, resolver: FakeResolver.new(txt, mx)).checks.index_by(&:record)
  end

  def dkim_txt_name = @domain.dkim_txt_name
  def dkim_txt_value = @domain.dkim_txt_value

  test "all green when published DNS matches" do
    checks = run_checks(
      mx: { "example.com" => [ [ 10, "mail.host.test" ] ] },
      txt: { "example.com" => [ "v=spf1 mx -all" ],
             dkim_txt_name => [ dkim_txt_value ],
             "_dmarc.example.com" => [ "v=DMARC1; p=none" ],
             "_mta-sts.example.com" => [ MtaSts.txt_record ],
             "_smtp._tls.example.com" => [ "v=TLSRPTv1; rua=mailto:tls-rpt@example.com" ] }
    )
    assert checks.values.all? { |c| c.status == :pass }, checks.values.inspect
  end

  test "MTA-STS: missing fails, a stale id warns, the current id passes" do
    assert_equal :fail, run_checks["MTA-STS"].status

    checks = run_checks(txt: { "_mta-sts.example.com" => [ "v=STSv1; id=oldpolicyid" ] })
    assert_equal :warn, checks["MTA-STS"].status
    assert_includes checks["MTA-STS"].note, "republish"

    assert_equal :pass, run_checks(txt: { "_mta-sts.example.com" => [ MtaSts.txt_record ] })["MTA-STS"].status
  end

  test "TLS-RPT: any published record passes, absence fails" do
    assert_equal :fail, run_checks["TLS-RPT"].status
    assert_equal :pass, run_checks(txt: { "_smtp._tls.example.com" => [ "v=TLSRPTv1; rua=mailto:elsewhere@other.test" ] })["TLS-RPT"].status
  end

  test "MX fails when no record points at the mail host, passes on any match" do
    checks = run_checks(mx: { "example.com" => [ [ 10, "elsewhere.test" ] ] })
    assert_equal :fail, checks["MX"].status
    assert_includes checks["MX"].note, "mail.host.test"

    checks = run_checks(mx: { "example.com" => [ [ 5, "elsewhere.test" ], [ 10, "mail.host.test" ] ] })
    assert_equal :pass, checks["MX"].status
  end

  test "SPF: missing fails, unrecognized mechanisms warn, mx or a:host pass" do
    assert_equal :fail, run_checks["SPF"].status
    assert_equal :warn, run_checks(txt: { "example.com" => [ "v=spf1 ip4:203.0.113.9 -all" ] })["SPF"].status
    assert_equal :pass, run_checks(txt: { "example.com" => [ "v=spf1 a:mail.host.test -all" ] })["SPF"].status
  end

  test "DKIM: compares the published p= against the key on disk" do
    assert_equal :fail, run_checks["DKIM"].status

    checks = run_checks(txt: { dkim_txt_name => [ dkim_txt_value ] })
    assert_equal :pass, checks["DKIM"].status

    other = "v=DKIM1; k=rsa; p=#{Base64.strict_encode64(OpenSSL::PKey::RSA.new(2048).public_to_der)}"
    checks = run_checks(txt: { dkim_txt_name => [ other ] })
    assert_equal :fail, checks["DKIM"].status
    assert_includes checks["DKIM"].note, "not this server's key"
  end

  test "DKIM is unknown when this server has no key" do
    @domain.update!(dkim_private_key: nil)
    assert_equal :unknown, run_checks["DKIM"].status
  end

  test "DMARC: found record is exposed for the advice engine" do
    dns = DnsCheck.for(@domain, resolver: FakeResolver.new({ "_dmarc.example.com" => [ "v=DMARC1; p=quarantine" ] }, {}))
    assert_equal "v=DMARC1; p=quarantine", dns.dmarc_record
    assert_equal :fail, run_checks["DMARC"].status # and absent => fail, no record
  end

  test "refresh! persists the checks as the domain's cached pills" do
    DnsCheck.refresh!(@domain, resolver: FakeResolver.new({ "example.com" => [ "v=spf1 mx -all" ] },
                                                          { "example.com" => [ [ 10, "mail.host.test" ] ] }))
    @domain.reload
    assert @domain.dns_checked_at.present?
    cached = @domain.cached_dns_checks.index_by(&:record)
    assert_equal :pass, cached["MX"].status
    assert_equal :pass, cached["SPF"].status
    assert_equal :fail, cached["DMARC"].status
    assert_includes cached["DMARC"].note, "no _dmarc record"
  end

  test "DNS failures surface as unknown, not fail" do
    failing = Struct.new(:x) do
      def txt(_name) = nil
      def mx(_name) = nil
    end
    checks = DnsCheck.for(@domain, resolver: failing.new(nil)).checks
    statuses = checks.map(&:status).uniq
    assert_equal [ :unknown ], statuses
  end
end
