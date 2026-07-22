require "test_helper"
require "mail_on_rails/clamav_scanner"
require_relative "../../test_helpers/fake_clamd"

# The scanner's whole contract: a three-way verdict, never an exception.
# Anything that isn't a definite OK or FOUND - garbage, silence, a dead
# port - must come back :unavailable, and callers decide policy.
class ClamavScannerTest < ActiveSupport::TestCase
  RAW = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def with_scanner_at(addr, timeout: nil)
    ENV["MAIL_ON_RAILS_CLAMAV_ADDR"] = addr
    ENV["MAIL_ON_RAILS_CLAMAV_TIMEOUT"] = timeout.to_s if timeout
    yield
  ensure
    ENV.delete("MAIL_ON_RAILS_CLAMAV_ADDR")
    ENV.delete("MAIL_ON_RAILS_CLAMAV_TIMEOUT")
  end

  test "disabled without an address" do
    assert_not MailOnRails::ClamavScanner.enabled?
    with_scanner_at("127.0.0.1:3310") { assert MailOnRails::ClamavScanner.enabled? }
  end

  test "clean reply" do
    FakeClamd.serving(:clean) do |addr|
      with_scanner_at(addr) do
        result = MailOnRails::ClamavScanner.scan(RAW)
        assert result.clean?
        assert_nil result.virus
      end
    end
  end

  test "infected reply carries the signature name" do
    FakeClamd.serving(:infected) do |addr|
      with_scanner_at(addr) do
        result = MailOnRails::ClamavScanner.scan(RAW)
        assert result.infected?
        assert_equal "Eicar-Test-Signature", result.virus
      end
    end
  end

  test "unparseable reply is unavailable, not clean" do
    FakeClamd.serving(:garbage) do |addr|
      with_scanner_at(addr) do
        assert MailOnRails::ClamavScanner.scan(RAW).unavailable?
      end
    end
  end

  test "refused connection is unavailable" do
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close

    with_scanner_at("127.0.0.1:#{port}") do
      assert MailOnRails::ClamavScanner.scan(RAW).unavailable?
    end
  end

  test "silent clamd is unavailable, bounded by the timeout" do
    FakeClamd.serving(:hang) do |addr|
      with_scanner_at(addr, timeout: 1) do
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = MailOnRails::ClamavScanner.scan(RAW)
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

        assert result.unavailable?
        assert_operator elapsed, :<, 5, "the timeout must bound a silent clamd"
      end
    end
  end
end
