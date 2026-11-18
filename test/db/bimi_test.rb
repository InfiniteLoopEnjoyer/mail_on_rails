# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/refresh_bimi_indicator_job", __dir__)
require "fake_resolver"
require "net/http"
require "socket"
require "openssl"
require "mail_on_rails/netserv/tls"
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

  # -- the view reads, delivery refreshes (2026-11-17 audit, L3) ----------------
  #
  # for_message is called while rendering a message. It used to create the
  # row and enqueue the evaluation - DNS queries to the sender's _dmarc
  # and default._bimi names, then an HTTPS fetch from a host the sender
  # chose - so opening (or a client prefetching) a message told its sender
  # when it was read. The view-facing call is now a cache read; the
  # refresh is queued when the message is delivered, which the sender
  # already knows about.

  def bimi_jobs
    ActiveJob::Base.queue_adapter.enqueued_jobs.select { |j| j["job_class"] == "MailOnRails::RefreshBimiIndicatorJob" }
  end

  def stored_message(from: "news@brand.test", dmarc: "pass")
    Struct.new(:from_address, :dmarc) do
      def auth_result(mechanism) = mechanism == "dmarc" ? dmarc : nil
    end.new(from, dmarc)
  end

  test "for_message only reads the cache: no row, no job, for an unknown or a stale domain" do
    assert_nil MailOnRails::BimiIndicator.for_message(stored_message)
    assert_equal 0, MailOnRails::BimiIndicator.count, "viewing a message must not create an indicator row"
    assert_empty bimi_jobs, "viewing a message must not queue a lookup at the sender's DNS"

    stale = MailOnRails::BimiIndicator.create!(domain: "brand.test", status: "pass", svg: CLEAN_SVG,
                                               checked_at: 3.days.ago)
    assert_equal stale, MailOnRails::BimiIndicator.for_message(stored_message), "yesterday's logo still shows"
    assert_empty bimi_jobs, "a stale row is refreshed by the next delivery, not by a view"

    pending = MailOnRails::BimiIndicator.create!(domain: "pending.test", checked_at: nil)
    assert_nil MailOnRails::BimiIndicator.for_message(stored_message(from: "a@pending.test"))
    assert_nil pending.reload.checked_at
    assert_empty bimi_jobs
  end

  test "refresh_later_for queues the evaluation at delivery, when due" do
    MailOnRails::BimiIndicator.refresh_later_for(stored_message)
    assert_equal [ [ "brand.test" ] ], bimi_jobs.map { |j| j["arguments"] }

    MailOnRails::BimiIndicator.find_by!(domain: "brand.test").update!(checked_at: Time.current, status: "none")
    MailOnRails::BimiIndicator.refresh_later_for(stored_message(from: "Other@Brand.TEST"))
    assert_equal 1, bimi_jobs.size, "a fresh row is not looked up again"

    MailOnRails::BimiIndicator.find_by!(domain: "brand.test").update!(checked_at: 2.days.ago)
    MailOnRails::BimiIndicator.refresh_later_for(stored_message)
    assert_equal 2, bimi_jobs.size, "a stale row is"
  end

  test "refresh_later_for does nothing for mail that could never show a logo" do
    MailOnRails::BimiIndicator.refresh_later_for(stored_message(dmarc: "fail"))
    MailOnRails::BimiIndicator.refresh_later_for(stored_message(dmarc: nil))
    MailOnRails::BimiIndicator.refresh_later_for(stored_message(from: nil))
    MailOnRails::BimiIndicator.refresh_later_for(stored_message(from: "no-domain"))
    MailOnRails::BimiIndicator.refresh_later_for(stored_message(from: "a@bad domain\r\nX: y"))
    MailOnRails::Settings.overrides = { bimi: false }
    MailOnRails::BimiIndicator.refresh_later_for(stored_message)

    assert_empty bimi_jobs
    assert_equal 0, MailOnRails::BimiIndicator.count
  ensure
    MailOnRails::Settings.reset!
  end

  # -- the logo fetch (2026-11-17 audit, L3 / todo M6) --------------------------
  #
  # The l= URL is whatever a sender's DNS says, fetched from this server's
  # network position.

  # Pins what the logo host resolves to (real Addrinfo objects, no network).
  def with_resolved(*addresses)
    singleton = Addrinfo.singleton_class
    original = Addrinfo.method(:getaddrinfo)
    asked = []
    singleton.define_method(:getaddrinfo) do |host, port, *_rest|
      asked << host
      addresses.flatten.map { |address| Addrinfo.tcp(address, port || 443) }
    end
    yield asked
  ensure
    singleton.define_method(:getaddrinfo, original)
  end

  # Replaces Net::HTTP.new for the block: +builder+ gets (host, port) and
  # returns the stand-in connection.
  def with_http(builder)
    original = Net::HTTP.method(:new)
    Net::HTTP.singleton_class.define_method(:new) { |host, port = nil, *_rest| builder.call(host, port) }
    yield
  ensure
    Net::HTTP.singleton_class.define_method(:new, original)
  end

  # A Net::HTTP stand-in that records how it was set up and answers
  # request_get with +response+ (or what +respond+ returns for the pinned
  # address - raise there to play an unreachable one).
  class FakeHttp
    attr_reader :host, :port, :pinned, :paths, :settings

    def initialize(host, port, response: nil, respond: nil)
      @host = host
      @port = port
      @response = response
      @respond = respond
      @paths = []
      @settings = {}
    end

    def ipaddr=(address)
      @pinned = address
    end

    %i[use_ssl open_timeout read_timeout max_retries].each do |name|
      define_method("#{name}=") { |value| @settings[name] = value }
    end

    def request_get(path, _headers = nil)
      @paths << path
      yield(@respond ? @respond.call(@pinned) : @response)
    end
  end

  def http_response(klass, code, body: nil, location: nil, chunks: nil)
    response = klass.new("1.1", code, "")
    response.define_singleton_method(:read_body) do |&block|
      chunks ? chunks.call(block) : block.call(body.to_s)
    end
    response["location"] = location if location
    response
  end

  def ok(body) = http_response(Net::HTTPOK, "200", body: body)

  NON_ROUTABLE_SAMPLES = %w[
    127.0.0.1 10.0.0.1 172.16.0.9 192.168.1.1 169.254.169.254
    0.0.0.0 0.1.2.3 100.64.0.1 100.127.255.254 192.0.2.10 198.18.0.1 198.51.100.7 203.0.113.9 224.0.0.1 255.255.255.255
    ::1 :: fe80::1 fc00::1 fd46:7ac3:4fd7::5 ::ffff:10.0.0.1 ::ffff:8.8.8.8 64:ff9b::a00:1 2001:db8::1 ff02::1
  ].freeze

  test "fetcher refuses every non-routable range, before any connection is made" do
    NON_ROUTABLE_SAMPLES.each do |address|
      error = with_resolved(address) do
        with_http(->(*) { flunk "connected to a logo host resolving to #{address}" }) do
          assert_raises(MailOnRails::BimiFetcher::Error, address) { MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg") }
        end
      end
      assert_match(/non-public/, error.message, address)
    end
  end

  test "fetcher refuses a mixed public and private answer outright" do
    with_resolved("93.184.216.34", "10.0.0.1") do
      with_http(->(*) { flunk "a mixed RRset must not be connected to at all" }) do
        assert_raises(MailOnRails::BimiFetcher::Error) { MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg") }
      end
    end
  end

  test "fetcher resolves once and connects to the address it vetted, verifying TLS for the hostname" do
    connections = []
    with_resolved("93.184.216.34") do |asked|
      with_http(->(host, port) { FakeHttp.new(host, port, response: ok(CLEAN_SVG)).tap { |http| connections << http } }) do
        assert_equal CLEAN_SVG, MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg?v=1")
      end
      assert_equal [ "logo.brand.test" ], asked, "one resolution: the vetted answer is the one connected to"
    end

    http = connections.sole
    assert_equal "93.184.216.34", http.pinned, "the socket must go to the vetted address, not a second lookup of the name"
    assert_equal [ "logo.brand.test", 443 ], [ http.host, http.port ], "SNI and certificate check stay on the hostname"
    assert_equal true, http.settings[:use_ssl]
    assert_equal 0, http.settings[:max_retries]
    assert_equal [ "/l.svg?v=1" ], http.paths
  end

  test "fetcher abandons an oversized body mid-stream instead of buffering it" do
    sent = 0
    endless = lambda do |block|
      loop do
        raise "read #{sent} bytes: streamed far past the cap" if sent > 10 * MailOnRails::BimiSvg::MAX_BYTES

        sent += 16_384
        block.call("x" * 16_384)
      end
    end
    response = http_response(Net::HTTPOK, "200", chunks: endless)
    # What the old fetch called: the whole body, however large.
    response.define_singleton_method(:body) { endless.call(->(_chunk) { }) }

    error = with_resolved("93.184.216.34") do
      with_http(->(host, port) { FakeHttp.new(host, port, response: response) }) do
        assert_raises(MailOnRails::BimiFetcher::Error) { MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg") }
      end
    end
    assert_match(/exceeds 32 KB/, error.message)
    assert_operator sent, :<=, MailOnRails::BimiSvg::MAX_BYTES + 16_384
  end

  test "fetcher vets and pins every redirect hop like the first URL" do
    connections = []
    answers = {
      "logo.brand.test" => http_response(Net::HTTPFound, "302", location: "https://cdn.brand.test/final.svg"),
      "cdn.brand.test" => ok(CLEAN_SVG)
    }
    resolutions = { "logo.brand.test" => "93.184.216.34", "cdn.brand.test" => "151.101.1.1" }
    singleton = Addrinfo.singleton_class
    original = Addrinfo.method(:getaddrinfo)
    singleton.define_method(:getaddrinfo) { |host, port, *_rest| [ Addrinfo.tcp(resolutions.fetch(host), port) ] }
    begin
      with_http(->(host, port) { FakeHttp.new(host, port, response: answers.fetch(host)).tap { |http| connections << http } }) do
        assert_equal CLEAN_SVG, MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg")
      end
      assert_equal [ [ "logo.brand.test", "93.184.216.34" ], [ "cdn.brand.test", "151.101.1.1" ] ],
                   connections.map { |http| [ http.host, http.pinned ] }

      # The classic: a public host redirecting into the internal network.
      resolutions["cdn.brand.test"] = "169.254.169.254"
      connections.clear
      error = with_http(->(host, port) { FakeHttp.new(host, port, response: answers.fetch(host)).tap { |http| connections << http } }) do
        assert_raises(MailOnRails::BimiFetcher::Error) { MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg") }
      end
      assert_match(/non-public/, error.message)
      assert_equal [ "logo.brand.test" ], connections.map(&:host), "the internal hop must never be connected to"
    ensure
      singleton.define_method(:getaddrinfo, original)
    end
  end

  test "fetcher refuses a redirect to plain http, a redirect loop, and non-https URLs" do
    to_http = http_response(Net::HTTPMovedPermanently, "301", location: "http://logo.brand.test/l.svg")
    to_self = http_response(Net::HTTPFound, "302", location: "/again.svg")
    with_resolved("93.184.216.34") do
      with_http(->(host, port) { FakeHttp.new(host, port, response: to_http) }) do
        error = assert_raises(MailOnRails::BimiFetcher::Error) { MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg") }
        assert_match(/must be https/, error.message)
      end
      hops = 0
      with_http(->(host, port) { hops += 1; FakeHttp.new(host, port, response: to_self) }) do
        error = assert_raises(MailOnRails::BimiFetcher::Error) { MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg") }
        assert_match(/too many redirects/, error.message)
      end
      assert_equal MailOnRails::BimiFetcher::MAX_REDIRECTS + 1, hops
    end

    [ "http://logo.brand.test/l.svg", "file:///etc/passwd", "ftp://logo.brand.test/l.svg", "https:///l.svg", "not a url", "" ].each do |url|
      with_http(->(*) { flunk "#{url.inspect} must not be fetched" }) do
        assert_raises(MailOnRails::BimiFetcher::Error, url.inspect) { MailOnRails::BimiFetcher.fetch(url) }
      end
    end
  end

  test "fetcher moves past an unreachable address but takes a server's answer as final" do
    tried = []
    respond = lambda do |address|
      tried << address
      raise Errno::ECONNREFUSED if address.include?(":")

      ok(CLEAN_SVG)
    end
    with_resolved("2606:4700::1111", "93.184.216.34") do
      with_http(->(host, port) { FakeHttp.new(host, port, respond: respond) }) do
        assert_equal CLEAN_SVG, MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg")
      end
      assert_equal [ "2606:4700::1111", "93.184.216.34" ], tried

      tried.clear
      not_found = ->(address) { tried << address; http_response(Net::HTTPNotFound, "404") }
      with_http(->(host, port) { FakeHttp.new(host, port, respond: not_found) }) do
        error = assert_raises(MailOnRails::BimiFetcher::Error) { MailOnRails::BimiFetcher.fetch("https://logo.brand.test/l.svg") }
        assert_match(/HTTP 404/, error.message)
      end
      assert_equal [ "2606:4700::1111" ], tried, "a 404 is not 'try the other address family'"
    end
  end

  # The same properties against a real TLS socket, so they rest on what
  # net/http actually does and not on a stand-in: a throwaway HTTPS server
  # on loopback whose certificate names logo.brand.test. That name exists
  # nowhere in DNS: the fetcher is told it resolves to 127.0.0.1 (and that
  # loopback passes the vet), so the request only arrives if the socket
  # really goes to the pinned address, and only verifies if the
  # certificate is still checked against the name.
  #
  # net/http verifies against the process-wide default store, so the
  # throwaway certificate (one for the suite; its key never leaves this
  # process) joins it for the rest of the test run.
  def self.logo_tls_context
    @logo_tls_context ||= begin
      pems = MailOnRails::Netserv::Tls.generate_self_signed([ "logo.brand.test" ])
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = OpenSSL::X509::Certificate.new(pems[:cert])
      ctx.key = OpenSSL::PKey.read(pems[:key])
      OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE.add_cert(ctx.cert)
      ctx
    end
  end

  def with_https_server(handler:)
    ctx = self.class.logo_tls_context
    listener = TCPServer.new("127.0.0.1", 0)
    server = Thread.new do
      loop do
        ssl = OpenSSL::SSL::SSLSocket.new(listener.accept, ctx)
        ssl.sync_close = true
        begin
          ssl.accept
          request = +""
          request << ssl.gets("\r\n") until request.end_with?("\r\n\r\n")
          handler.call(ssl, request)
        rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
          nil # the client hung up (the point of the oversize test) or refused the cert
        ensure
          ssl.close rescue nil
        end
      end
    rescue IOError, SystemCallError
      nil # listener closed
    end
    yield listener.addr[1]
  ensure
    listener&.close
    server&.kill
  end

  # A fetcher for which every name resolves to the loopback test server
  # and loopback is allowed (the vet itself is covered above).
  def loopback_fetcher
    fetcher = MailOnRails::BimiFetcher.new
    fetcher.define_singleton_method(:resolve) { |_host, _port| [ "127.0.0.1" ] }
    fetcher.define_singleton_method(:routable?) { |_address| true }
    fetcher
  end

  test "fetcher over real TLS: pinned address, certificate checked against the hostname" do
    served = []
    handler = lambda do |ssl, request|
      served << request[/\AGET (\S+)/, 1]
      ssl.write("HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: #{CLEAN_SVG.bytesize}\r\nConnection: close\r\n\r\n#{CLEAN_SVG}")
    end

    with_https_server(handler: handler) do |port|
      assert_equal CLEAN_SVG, loopback_fetcher.fetch("https://logo.brand.test:#{port}/l.svg")
      assert_equal [ "/l.svg" ], served

      # Same server, same pinned address, a name its certificate does not
      # carry: the pin must not have switched hostname verification off.
      error = assert_raises(MailOnRails::BimiFetcher::Error) { loopback_fetcher.fetch("https://other.brand.test:#{port}/l.svg") }
      assert_match(/\ATLS: /, error.message)
      assert_equal [ "/l.svg" ], served, "no request may be sent over an unverified channel"
    end
  end

  test "fetcher over real TLS: an endless body is cut off at the cap" do
    written = 0
    handler = lambda do |ssl, _request|
      ssl.write("HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nConnection: close\r\n\r\n")
      loop do
        ssl.write("x" * 16_384)
        written += 16_384
        break if written > 64 * 1024 * 1024 # a fetcher that reads it all fails below
      end
    end

    with_https_server(handler: handler) do |port|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      error = assert_raises(MailOnRails::BimiFetcher::Error) { loopback_fetcher.fetch("https://logo.brand.test:#{port}/l.svg") }
      assert_match(/exceeds 32 KB/, error.message)
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
    end
    assert_operator written, :<, 16 * 1024 * 1024, "the server got to send #{written} bytes"
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
