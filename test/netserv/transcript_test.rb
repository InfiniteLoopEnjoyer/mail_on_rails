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

  # M9 (audit 2026-11-17): the byte cap spared the newest line whatever
  # its size, so a single multi-megabyte line (an IMAP FETCH response
  # carrying a message) made the buffer - and the stored transcript row -
  # that large.
  def test_a_single_line_over_the_byte_cap_is_cut_to_fit_it
    t = MailOnRails::Netserv::Transcript.new(max_bytes: 1024)
    t.inbound("a1 FETCH 1 (BODY[])")
    t.outbound("* 1 FETCH (BODY[] {5000000}" + "SECRET " * 700_000)

    assert_operator t.to_s.bytesize, :<=, 1024
    assert_includes t.to_s, "=> * 1 FETCH (BODY[] {5000000}", "the start of the line is kept"
    assert_match(/\.\.\. \(\d+ bytes\)\z/, t.to_s, "and its real size noted")

    t.outbound("a1 OK FETCH completed")
    assert_operator t.to_s.bytesize, :<=, 1024
    assert t.to_s.end_with?("=> a1 OK FETCH completed"), "later lines still land"
  end

  def test_the_byte_cap_holds_after_every_push_whatever_the_line_sizes
    cap = 600
    t = MailOnRails::Netserv::Transcript.new(max_bytes: cap)
    [ 10, 599, 600, 601, 5_000, 1, 300, 299, 100_000, 50 ].each do |size|
      t.inbound("x" * size)
      assert_operator t.to_s.bytesize, :<=, cap, "after a #{size}-byte line"
      refute t.empty?
    end
  end

  # The cut is by bytes and may split a character; the flush scrubs it.
  def test_a_cut_through_a_multibyte_character_still_flushes_as_valid_utf8
    t = MailOnRails::Netserv::Transcript.new(max_bytes: 100)
    t.inbound("é" * 500)

    assert t.to_s.valid_encoding?
    assert_operator t.to_s.bytesize, :<=, 100
  end

  # A client line is one transcript entry however many line breaks it
  # smuggles: a raw CR/LF would let "NOOP\n=> 235 Authentication successful"
  # read as a server reply on the honeypot page.
  def test_bare_cr_and_lf_in_a_line_cannot_forge_another_entry
    t = MailOnRails::Netserv::Transcript.new
    t.inbound("NOOP\n=> 235 Authentication successful")
    t.inbound("EHLO x\r\n<= AUTH PLAIN dXNlcg==\rtrailing")
    t.outbound("250 ok")
    lines = t.to_s.split("\n")

    assert_equal 3, lines.size
    assert_equal "<= NOOP\\n=> 235 Authentication successful", lines[0]
    assert_equal "<= EHLO x\\r\\n<= AUTH PLAIN dXNlcg==\\rtrailing", lines[1]
    assert_equal "=> 250 ok", lines[2]
    assert_equal 1, t.to_s.scan(/^=> /).size, "only the real server reply starts an entry"
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
