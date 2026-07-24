require "test_helper"
require "mail_on_rails/rspamd_analyzer"
require_relative "../../test_helpers/fake_rspamd"

# The analyzer's contract: turn rspamd's symbol soup into mechanism verdicts
# and an Authentication-Results string, forward the connection facts rspamd
# needs, and never raise - any transport or parse failure is :unavailable so
# callers decide policy.
class RspamdAnalyzerTest < ActiveSupport::TestCase
  RAW = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"

  # A typical clean rspamd verdict: SPF/DKIM/DMARC all allow, no action.
  PASS = {
    "action" => "no action", "score" => 0.1, "required_score" => 6.0,
    "symbols" => { "R_SPF_ALLOW" => {}, "R_DKIM_ALLOW" => {}, "DMARC_POLICY_ALLOW" => {} }
  }.freeze

  def with_rspamd_at(addr, timeout: nil)
    ENV["SMTP_RSPAMD_ADDR"] = addr
    ENV["SMTP_RSPAMD_TIMEOUT"] = timeout.to_s if timeout
    yield
  ensure
    ENV.delete("SMTP_RSPAMD_ADDR")
    ENV.delete("SMTP_RSPAMD_TIMEOUT")
  end

  test "disabled without an address" do
    assert_not MailOnRails::RspamdAnalyzer.enabled?
    with_rspamd_at("127.0.0.1:11333") { assert MailOnRails::RspamdAnalyzer.enabled? }
  end

  test "maps allow symbols to pass verdicts and an Authentication-Results string" do
    FakeRspamd.serving(PASS) do |addr, _captured|
      with_rspamd_at(addr) do
        result = MailOnRails::RspamdAnalyzer.analyze(RAW, ip: "203.0.113.9", helo: "mx.remote.test",
                                                     mail_from: "sender@remote.test")
        assert result.ok?
        assert_equal "pass", result.spf
        assert_equal "pass", result.dkim
        assert_equal "pass", result.dmarc
        assert_match(/spf=pass/, result.auth_results)
        assert_match(/dkim=pass/, result.auth_results)
        assert_match(/dmarc=pass/, result.auth_results)
        assert_not result.spam?
      end
    end
  end

  test "maps failure symbols and flags a reject action as spam" do
    verdict = {
      "action" => "reject", "score" => 15.0, "required_score" => 6.0,
      "symbols" => { "R_SPF_FAIL" => {}, "R_DKIM_REJECT" => {}, "DMARC_POLICY_REJECT" => {} }
    }
    FakeRspamd.serving(verdict) do |addr, _captured|
      with_rspamd_at(addr) do
        result = MailOnRails::RspamdAnalyzer.analyze(RAW)
        assert_equal "fail", result.spf
        assert_equal "fail", result.dkim
        assert_equal "fail", result.dmarc
        assert result.spam?
      end
    end
  end

  test "forwards the connection facts rspamd needs for SPF/DMARC" do
    FakeRspamd.serving(PASS) do |addr, captured|
      with_rspamd_at(addr) do
        MailOnRails::RspamdAnalyzer.analyze(RAW, ip: "203.0.113.9", helo: "mx.remote.test",
                                            mail_from: "sender@remote.test", rcpt: "user@local.test")
        assert_equal "203.0.113.9", captured["ip"]
        assert_equal "mx.remote.test", captured["helo"]
        assert_equal "sender@remote.test", captured["from"]
        assert_equal "user@local.test", captured["rcpt"]
      end
    end
  end

  test "strips CR/LF from facts so a header cannot be injected" do
    FakeRspamd.serving(PASS) do |addr, captured|
      with_rspamd_at(addr) do
        MailOnRails::RspamdAnalyzer.analyze(RAW, helo: "mx.remote.test\r\nInjected: 1")
        assert_equal "mx.remote.testInjected: 1", captured["helo"]
        assert_nil captured["injected"]
      end
    end
  end

  test "missing mechanism symbols leave that mechanism out of the string" do
    FakeRspamd.serving({ "action" => "no action", "symbols" => { "R_SPF_ALLOW" => {} } }) do |addr, _captured|
      with_rspamd_at(addr) do
        result = MailOnRails::RspamdAnalyzer.analyze(RAW)
        assert_equal "pass", result.spf
        assert_nil result.dkim
        assert_nil result.dmarc
        assert_equal "spf=pass", result.auth_results.split("; ", 2).last
      end
    end
  end

  test "a non-2xx response is unavailable, not a verdict" do
    FakeRspamd.serving({ "error" => "boom" }, status: 500) do |addr, _captured|
      with_rspamd_at(addr) do
        assert MailOnRails::RspamdAnalyzer.analyze(RAW).unavailable?
      end
    end
  end

  test "an unparseable body is unavailable, not clean" do
    FakeRspamd.serving("this is not json") do |addr, _captured|
      with_rspamd_at(addr) do
        assert MailOnRails::RspamdAnalyzer.analyze(RAW).unavailable?
      end
    end
  end

  test "a refused connection is unavailable" do
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close

    with_rspamd_at("127.0.0.1:#{port}") do
      assert MailOnRails::RspamdAnalyzer.analyze(RAW).unavailable?
    end
  end

  test "a silent rspamd is unavailable, bounded by the timeout" do
    FakeRspamd.serving(PASS, hang: true) do |addr, _captured|
      with_rspamd_at(addr, timeout: 1) do
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = MailOnRails::RspamdAnalyzer.analyze(RAW)
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

        assert result.unavailable?
        assert_operator elapsed, :<, 5, "the timeout must bound a silent rspamd"
      end
    end
  end
end
