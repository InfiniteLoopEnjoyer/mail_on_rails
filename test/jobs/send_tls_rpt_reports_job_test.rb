require "test_helper"
require "zlib"
require "mail_on_rails/smtp/sender_auth/dns"

# The daily RFC 8460 rollup: yesterday's TlsRptEvents become one gzipped
# JSON report per recipient domain that asks for one via its TLSRPT
# record; domains without a record are skipped.
class SendTlsRptReportsJobTest < ActiveSupport::TestCase
  class FakeDns
    def initialize(txt = {})
      @txt = txt
    end

    def txt(name)
      @txt.fetch(name, [])
    end
  end

  def seed_event(domain: "remote.test", type: "sts", result: nil, mx: "mx.remote.test", detail: nil, at: Date.yesterday.noon)
    TlsRptEvent.create!(policy_domain: domain, policy_type: type, receiving_mx: mx,
                        result_type: result, failure_detail: detail, occurred_at: at)
  end

  def run_job(txt)
    job = SendTlsRptReportsJob.new
    fake = FakeDns.new(txt)
    job.define_singleton_method(:dns) { fake }
    job.perform(Date.yesterday)
  end

  RUA_TXT = { "_smtp._tls.remote.test" => [ "v=TLSRPTv1; rua=mailto:tls-reports@remote.test" ] }.freeze

  test "rolls a domain's day into a gzipped report mailed to its rua" do
    Domain.create!(name: "example.com")
    2.times { seed_event }
    seed_event(result: "validation-failure", detail: "certificate mismatch")
    seed_event(type: "tlsa")
    seed_event(at: 3.days.ago) # outside the window

    run_job(RUA_TXT)

    queued = SmtpOutboundMessage.sole
    assert_equal "tls-reports@remote.test", queued.recipient
    assert_equal "tls-rpt@example.com", queued.mail_from

    mail = Mail.read_from_string(queued.data)
    assert_equal "remote.test", mail.header["TLS-Report-Domain"].value
    assert_match(/Report Domain: remote\.test/, mail.subject)

    attachment = mail.attachments.first
    assert_equal "application/tlsrpt+gzip", attachment.mime_type
    assert_match(/\Aexample\.com!remote\.test!\d+!\d+\.json\.gz\z/, attachment.filename)

    report = JSON.parse(Zlib.gunzip(attachment.body.decoded))
    assert_equal "example.com", report["organization-name"]

    sts = report["policies"].find { |p| p.dig("policy", "policy-type") == "sts" }
    assert_equal 2, sts["summary"]["total-successful-session-count"]
    assert_equal 1, sts["summary"]["total-failure-session-count"]
    failure = sts["failure-details"].sole
    assert_equal [ "validation-failure", 1, "mx.remote.test", "certificate mismatch" ],
                 failure.values_at("result-type", "failed-session-count", "receiving-mx-hostname", "failure-reason-code")

    tlsa = report["policies"].find { |p| p.dig("policy", "policy-type") == "tlsa" }
    assert_equal 1, tlsa["summary"]["total-successful-session-count"]
    assert_nil tlsa["failure-details"]
  end

  test "includes the cached MTA-STS policy lines in the sts policy block" do
    MtaStsPolicy.create!(domain: "remote.test", sts_id: "id1", mode: "enforce",
                         max_age: 86_400, mx_patterns: [ "mx.remote.test" ], fetched_at: Time.current)
    seed_event

    run_job(RUA_TXT)

    report = JSON.parse(Zlib.gunzip(Mail.read_from_string(SmtpOutboundMessage.sole.data).attachments.first.body.decoded))
    assert_includes report["policies"].first.dig("policy", "policy-string"), "mode: enforce"
  end

  test "a domain without a TLSRPT record gets no report" do
    seed_event

    run_job({})

    assert_equal 0, SmtpOutboundMessage.count
  end

  test "one report per rua destination, capped" do
    seed_event

    run_job("_smtp._tls.remote.test" =>
      [ "v=TLSRPTv1; rua=mailto:a@remote.test,mailto:b@remote.test,https://cdn.example/report" ])

    assert_equal %w[a@remote.test b@remote.test], SmtpOutboundMessage.pluck(:recipient).sort
  end

  test "prune! enforces retention" do
    seed_event(at: 8.days.ago)
    fresh = seed_event

    assert_equal 1, TlsRptEvent.prune!
    assert_equal [ fresh.id ], TlsRptEvent.pluck(:id)
  end
end
