# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/mime_limits"

# The raw-bytes structure guard: measures nesting depth and part count in
# one pass, without the Mail gem, and stops early past either cap.
class MimeLimitsTest < Minitest::Test
  HEADERS = "From: x@remote.test\r\nTo: a@example.test\r\nSubject: s\r\nMIME-Version: 1.0\r\n"

  # depth nested multipart/mixed containers, each with its own boundary,
  # closed in reverse - the audit's SystemStackError reproducer.
  def nested(depth)
    raw = +"#{HEADERS}Content-Type: multipart/mixed; boundary=b0\r\n\r\n"
    depth.times { |i| raw << "--b#{i}\r\nContent-Type: multipart/mixed; boundary=b#{i + 1}\r\n\r\n" }
    raw << "--b#{depth}\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b#{depth}--\r\n"
    depth.times { |i| raw << "--b#{depth - 1 - i}--\r\n" }
    raw
  end

  # n sibling multipart containers under one root: wide, not deep.
  def siblings(n)
    raw = +"#{HEADERS}Content-Type: multipart/mixed; boundary=b0\r\n\r\n"
    n.times do |i|
      raw << "--b0\r\nContent-Type: multipart/mixed; boundary=s#{i}\r\n\r\n--s#{i}\r\nContent-Type: text/plain\r\n\r\nhi\r\n--s#{i}--\r\n"
    end
    raw << "--b0--\r\n"
  end

  def measure(raw)
    MailOnRails::MimeLimits.measure(raw)
  end

  test "a plain message has no structure" do
    m = measure("#{HEADERS}Content-Type: text/plain\r\n\r\nhello\r\n-- \r\nsig\r\n")
    assert_equal [ 0, 0 ], [ m.depth, m.parts ]
    assert_not m.too_complex?
  end

  test "counts depth and parts of an ordinary multipart message" do
    raw = "#{HEADERS}Content-Type: multipart/mixed;\r\n\tboundary=\"outer\"\r\n\r\n" \
          "--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n" \
          "--inner\r\nContent-Type: text/plain\r\n\r\nhi\r\n--inner\r\nContent-Type: text/html\r\n\r\n<b>hi</b>\r\n--inner--\r\n" \
          "--outer\r\nContent-Type: application/pdf; name=a.pdf\r\n\r\nAAAA\r\n--outer--\r\n"
    m = measure(raw)
    assert_equal 2, m.depth, "the folded boundary= parameter must be seen"
    assert_equal 4, m.parts
    assert_not m.too_complex?
  end

  test "nesting below the cap is fine, past it is too complex" do
    assert_equal MailOnRails::MimeLimits::MAX_DEPTH, measure(nested(MailOnRails::MimeLimits::MAX_DEPTH - 1)).depth
    assert_not MailOnRails::MimeLimits.too_complex?(nested(MailOnRails::MimeLimits::MAX_DEPTH - 1))
    assert MailOnRails::MimeLimits.too_complex?(nested(MailOnRails::MimeLimits::MAX_DEPTH))
  end

  test "the depth-5000 reproducer is measured in a bounded time" do
    raw = nested(5000)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert MailOnRails::MimeLimits.too_complex?(raw)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.5
  end

  test "width counts as parts, not depth" do
    m = measure(siblings(300))
    assert_equal 2, m.depth
    assert_equal 600, m.parts
    assert_not m.too_complex?
    assert MailOnRails::MimeLimits.too_complex?(siblings(MailOnRails::MimeLimits::MAX_PARTS))
  end

  test "an outer delimiter closes unterminated inner parts" do
    raw = "#{HEADERS}Content-Type: multipart/mixed; boundary=o\r\n\r\n" +
          20.times.map { |i| "--o\r\nContent-Type: multipart/mixed; boundary=i#{i}\r\n\r\n--i#{i}\r\nContent-Type: text/plain\r\n\r\nx\r\n" }.join +
          "--o--\r\n"
    assert_equal 2, measure(raw).depth
  end

  test "invalid utf-8 and body lines that look like delimiters do not upset it" do
    raw = "#{HEADERS}Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n" \
          "--notdeclared\r\n--\r\n\xFF\xFE boundary=nope\r\n--b--\r\n"
    m = measure(raw.b)
    assert_equal [ 1, 1 ], [ m.depth, m.parts ]
  end
end
