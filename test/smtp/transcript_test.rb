require "test_helper"
require "mail_on_rails/netserv/transcript"

# The honeypot transcript is a bounded ring buffer: an attacker holding a
# canary session open must not be able to grow it without limit.
class TranscriptTest < Minitest::Test
  def test_records_direction_prefixed_lines_in_order
    t = MailOnRails::Netserv::Transcript.new
    t.inbound("EHLO x")
    t.outbound("250 ok")
    assert_equal "<= EHLO x\n=> 250 ok", t.to_s
  end

  def test_drops_oldest_lines_past_the_line_cap
    t = MailOnRails::Netserv::Transcript.new(max_lines: 3)
    5.times { |i| t.inbound("line #{i}") }
    lines = t.to_s.split("\n")
    assert_equal 3, lines.size
    assert_equal "<= line 4", lines.last
    refute_includes t.to_s, "line 0"
  end

  def test_bounds_total_bytes
    t = MailOnRails::Netserv::Transcript.new(max_lines: 10_000, max_bytes: 200)
    50.times { |i| t.inbound("x" * 40 + i.to_s) }
    assert_operator t.to_s.bytesize, :<=, 400 # cap plus one straddling line
  end

  # An attacker embedding a NUL byte (or invalid UTF-8) in a command must not
  # be able to make the PostgreSQL insert of their own honeypot event raise.
  def test_flush_strips_nul_and_scrubs_invalid_utf8
    t = MailOnRails::Netserv::Transcript.new
    t.inbound("EHLO ev\u0000il")
    t.inbound("bad byte \xFF".dup.force_encoding("UTF-8"))
    flushed = t.to_s

    refute_includes flushed, "\u0000"
    assert flushed.valid_encoding?, "flushed transcript must be valid UTF-8"
    assert_includes flushed, "evil"
  end
end
