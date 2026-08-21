# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/refresh_bimi_indicator_job", __dir__)
require File.expand_path("../smtp/fake_resolver", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# BIMI, both directions: the strict SVG profile, the receiver-side
# DMARC-gated evaluation and cache, and the sender-side upload validation.
class BimiTest < DbSuite::TestCase
  CLEAN_SVG = %(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#c00"/></svg>)

  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
  end

  # -- the SVG profile ------------------------------------------------------

  test "clean static SVG passes and round-trips" do
    sanitized = MailOnRails::BimiSvg.sanitize(CLEAN_SVG)
    assert_includes sanitized, "<circle"
  end

  test "hostile SVG constructs are rejected outright" do
    rejects = {
      "script" => %(<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>),
      "event handler" => %(<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>),
      "external image" => %(<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.test/x.png"/></svg>),
      "external use" => %(<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.test/x.svg#a"/></svg>),
      "external css url" => %(<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill: url(https://evil.test/f)"/></svg>),
      "style import" => %(<svg xmlns="http://www.w3.org/2000/svg"><style>@import "https://evil.test/x.css";</style></svg>),
      "foreignObject" => %(<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"/></foreignObject></svg>),
      "animation" => %(<svg xmlns="http://www.w3.org/2000/svg"><rect><animate attributeName="x" from="0" to="9"/></rect></svg>),
      "dtd" => %(<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>),
      "not svg" => %(<html xmlns="http://www.w3.org/1999/xhtml"/>),
      "not xml" => "hello",
      "oversize" => %(<svg xmlns="http://www.w3.org/2000/svg"><desc>#{"x" * 40_000}</desc></svg>)
    }
    rejects.each do |label, svg|
      assert_raises(MailOnRails::BimiSvg::Invalid, "#{label} must be rejected") do
        MailOnRails::BimiSvg.sanitize(svg)
      end
    end
  end

  test "internal references stay allowed" do
    svg = %(<svg xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g"/></defs><rect fill="url(#g)"/></svg>)
    assert MailOnRails::BimiSvg.valid?(svg)
  end

  # -- receiver-side evaluation ---------------------------------------------

  ENFORCED_DMARC = { "_dmarc.brand.test" => [ "v=DMARC1; p=reject; rua=mailto:d@brand.test" ] }.freeze

  class FakeFetcher
    def initialize(body) = @body = body
    def fetch(url) = @body.respond_to?(:call) ? @body.call(url) : @body
  end

  def evaluate(txt:, body: CLEAN_SVG)
    MailOnRails::BimiIndicator.evaluate("brand.test", dns: FakeResolver.new(txt: txt), fetcher: FakeFetcher.new(body))
  end

  test "enforced DMARC + record + clean logo passes" do
    result = evaluate(txt: ENFORCED_DMARC.merge(
      "default._bimi.brand.test" => [ "v=BIMI1; l=https://brand.test/logo.svg; a=https://brand.test/vmc.pem" ]
    ))

    assert_equal "pass", result[:status]
    assert_includes result[:svg], "<circle"
    assert result[:evidence], "the a= evidence presence must be recorded"
  end

  test "unenforced or missing DMARC fails the gate" do
    [ [], [ "v=DMARC1; p=none" ], [ "v=DMARC1; p=quarantine; pct=50" ] ].each do |dmarc|
      result = evaluate(txt: { "_dmarc.brand.test" => dmarc,
                               "default._bimi.brand.test" => [ "v=BIMI1; l=https://brand.test/logo.svg" ] })
      assert_equal "fail", result[:status], "#{dmarc.inspect} must not qualify for BIMI"
    end
  end

  test "no record is none, an empty l= is declined, a hostile logo fails" do
    assert_equal "none", evaluate(txt: ENFORCED_DMARC)[:status]

    declined = evaluate(txt: ENFORCED_DMARC.merge("default._bimi.brand.test" => [ "v=BIMI1; l=;" ]))
    assert_equal "declined", declined[:status]

    hostile = evaluate(txt: ENFORCED_DMARC.merge("default._bimi.brand.test" => [ "v=BIMI1; l=https://brand.test/x.svg" ]),
                       body: %(<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>))
    assert_equal "fail", hostile[:status]
    assert_match(/script/, hostile[:error])
  end

  test "org-domain fallback finds the record for a subdomain sender" do
    txt = { "_dmarc.news.brand.test" => [],
            "_dmarc.brand.test" => [ "v=DMARC1; p=reject" ],
            "default._bimi.news.brand.test" => [],
            "default._bimi.brand.test" => [ "v=BIMI1; l=https://brand.test/logo.svg" ] }
    result = MailOnRails::BimiIndicator.evaluate("news.brand.test", dns: FakeResolver.new(txt: txt),
                                                 fetcher: FakeFetcher.new(CLEAN_SVG))

    assert_equal "pass", result[:status]
  end

  test "refresh! persists and for_message gates on the message's own DMARC pass" do
    row = MailOnRails::BimiIndicator.create!(domain: "brand.test", status: "pass", svg: CLEAN_SVG,
                                             checked_at: Time.current)

    passing = Struct.new(:from_address) do
      def auth_result(mechanism) = mechanism == "dmarc" ? "pass" : nil
    end.new("news@brand.test")
    failing = Struct.new(:from_address) do
      def auth_result(_mechanism) = "fail"
    end.new("news@brand.test")

    assert_equal row, MailOnRails::BimiIndicator.for_message(passing)
    assert_nil MailOnRails::BimiIndicator.for_message(failing),
               "a message that failed DMARC must never borrow the logo"

    MailOnRails::Settings.overrides = { bimi: false }
    assert_nil MailOnRails::BimiIndicator.for_message(passing)
  ensure
    MailOnRails::Settings.reset!
  end

  test "lookup enqueues a refresh only when stale" do
    assert_enqueued_jobs = lambda do
      ActiveJob::Base.queue_adapter.enqueued_jobs.count { |j| j["job_class"] == "MailOnRails::RefreshBimiIndicatorJob" }
    end

    MailOnRails::BimiIndicator.lookup("brand.test")
    assert_equal 1, assert_enqueued_jobs.call, "a missing row must enqueue an evaluation"

    MailOnRails::BimiIndicator.find_by(domain: "brand.test").update!(checked_at: Time.current, status: "none")
    MailOnRails::BimiIndicator.lookup("brand.test")
    assert_equal 1, assert_enqueued_jobs.call, "a fresh row must not enqueue again"
  end

  # -- sender side ------------------------------------------------------------

  test "domain upload is sanitized on save and rejected when hostile" do
    domain = MailOnRails::Domain.create!(name: "example.test", bimi_svg: CLEAN_SVG)
    assert_includes domain.bimi_svg, "<circle"
    assert_equal "default._bimi.example.test", domain.bimi_txt_name
    assert_equal "v=BIMI1; l=https://mail.example.test/bimi/example.test/logo.svg;",
                 domain.bimi_txt_value("mail.example.test")

    domain.bimi_svg = %(<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>)
    assert_not domain.valid?
    assert_match(/event handler/, domain.errors[:bimi_svg].first)
  end
end
