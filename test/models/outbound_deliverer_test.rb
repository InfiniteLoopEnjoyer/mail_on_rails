require "test_helper"

class OutboundDelivererTest < ActiveSupport::TestCase
  setup do
    @deliverer = OutboundDeliverer.new
  end

  def outbound(mail_from:, from_header:)
    headers = from_header ? "From: #{from_header}\r\n" : ""
    SmtpOutboundMessage.new(mail_from: mail_from, recipient: "rcpt@remote.test",
                            data: "#{headers}Subject: hi\r\n\r\nbody\r\n")
  end

  # Swap Rails.logger for a capturing one (minitest/mock isn't bundled -
  # same reason the clamav/rspamd stub helpers are hand-rolled).
  def capture_warnings
    io = StringIO.new
    original = Rails.logger
    Rails.logger = ActiveSupport::Logger.new(io)
    yield
    io.string
  ensure
    Rails.logger = original
  end

  def with_mx_records(records)
    singleton = Resolv::DNS.singleton_class
    original = Resolv::DNS.method(:open)
    singleton.define_method(:open) { |*_args, &_blk| records }
    yield
  ensure
    singleton.define_method(:open, original)
  end

  test "signs with the From: header domain's DB key, not the envelope domain" do
    Domain.create!(name: "header.test")
    Domain.create!(name: "envelope.test")
    signed = @deliverer.send(:signed, outbound(mail_from: "user@envelope.test", from_header: "Sender <user@header.test>"))
    assert_match(/^DKIM-Signature:.*d=header\.test;/m, signed)
  end

  test "falls back to the envelope domain when the From header is missing" do
    Domain.create!(name: "envelope.test")
    signed = @deliverer.send(:signed, outbound(mail_from: "user@envelope.test", from_header: nil))
    assert_match(/^DKIM-Signature:.*d=envelope\.test;/m, signed)
  end

  test "goes out unsigned, with a warning, when the domain has no key" do
    raw = outbound(mail_from: "user@nokey.test", from_header: "user@nokey.test")
    warnings = capture_warnings do
      assert_equal raw.data, @deliverer.send(:signed, raw)
    end
    assert_includes warnings, "UNSIGNED"
    assert_includes warnings, "nokey.test"
  end

  test "unsignable data goes out unsigned with a warning rather than raising" do
    Domain.create!(name: "envelope.test")
    raw = SmtpOutboundMessage.new(mail_from: "user@envelope.test", recipient: "rcpt@remote.test",
                                  data: "no header/body separator")
    warnings = capture_warnings do
      assert_equal raw.data, @deliverer.send(:signed, raw)
    end
    assert_includes warnings, "UNSIGNED"
  end

  test "equal-preference MX records are shuffled, lower preference still first" do
    mxs = [ mx(20, "backup.example.com"), mx(10, "a.example.com"), mx(10, "b.example.com") ]
    orders = Set.new
    20.times do
      with_mx_records(mxs) do
        hosts = @deliverer.send(:mx_hosts, "example.com").map(&:first)
        assert_equal "backup.example.com", hosts.last, "higher preference must sort last"
        orders << hosts.first(2)
      end
    end
    assert_equal 2, orders.size, "both orderings of the tied pair should occur across runs"
  end

  def mx(preference, host)
    Resolv::DNS::Resource::IN::MX.new(preference, Resolv::DNS::Name.create(host))
  end
end
