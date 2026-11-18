# frozen_string_literal: true

require_relative "test_helper"
require "mail"
require "stringio"
require "mail_on_rails/header_field"

# HeaderField is the one place that decides where a field name ends. The
# reference is the Mail gem, which the mailroom and the web UI parse with:
# whatever it accepts as a field called X, the raw-byte scanners must find
# under X too - and may find more, never less.
class HeaderFieldTest < Minitest::Test
  HeaderField = MailOnRails::HeaderField

  # The Mail gem warns on stderr for every name it refuses.
  def quietly
    stderr = $stderr
    $stderr = StringIO.new
    yield
  rescue StandardError
    false
  ensure
    $stderr = stderr
  end

  # Every single byte, as the gap between a name and its colon.
  test "the matcher finds every field the Mail gem files under that name" do
    matcher = HeaderField.matcher("X-Original-To")
    accepted = []
    (0..255).each do |byte|
      next if byte == 0x3a # the colon itself

      field = "X-Original-To".b + byte.chr + ": victim@local.test".b
      mail_gem_reads_it = quietly { Mail::Field.parse(field.dup)&.name.to_s.casecmp?("X-Original-To") }
      next unless mail_gem_reads_it

      accepted << byte
      assert field.match?(matcher), "byte 0x#{byte.to_s(16)}: the Mail gem reads X-Original-To, the matcher does not"
      assert_equal "X-Original-To", HeaderField.name(field)
    end
    # Ruby's rstrip set. If the gem ever widens it, this says so.
    assert_equal [ 0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20 ], accepted
  end

  test "the matcher takes VT, FF, NUL, DEL, 8-bit and mixed runs as the gap" do
    matcher = HeaderField.matcher("from", "sender")
    [ "", " ", "\t", "\v", "\f", "\x00", "\x7f", "\xA0".b, " \v\t\f ", "\r\n " ].each do |gap|
      assert "From#{gap}: a@b.test".b.match?(matcher), "gap #{gap.inspect}"
      assert "SENDER#{gap}:a@b.test".b.match?(matcher), "gap #{gap.inspect}"
      assert "#{gap}From: a@b.test".b.match?(matcher), "leading gap #{gap.inspect}"
    end
  end

  test "the matcher does not reach into longer names or past the colon" do
    matcher = HeaderField.matcher("from")
    assert_not "From-Extra: x".match?(matcher)
    assert_not "Fromx: x".match?(matcher)
    assert_not "X-From: x".match?(matcher)
    assert_not "Subject: from: x".match?(matcher)
    assert_not "from".match?(matcher)
  end

  test "non-literal names are regexp fragments" do
    matcher = HeaderField.matcher("X-MailOnRails-[\\w-]+", "Return-Path", literal: false)
    assert "x-mailonrails-client-ip\v: 1.2.3.4".match?(matcher)
    assert "Return-Path\f: <a@b>".match?(matcher)
    assert_not "X-MailOnRails: x".match?(matcher)
  end

  test "name is the text before the colon minus what trails it; nil without a colon" do
    assert_equal "From", HeaderField.name("From: a@b")
    assert_equal "From", HeaderField.name("From \t\v\f\x00: a@b")
    assert_equal "From", HeaderField.name("\v From: a@b"), "the gem lstrips the first field; so does this"
    assert_equal "Fr\vom", HeaderField.name("Fr\vom: a@b"), "a byte inside the name makes it another name"
    assert_nil HeaderField.name("no colon here")
    assert_nil HeaderField.name(nil)
  end

  test "control_in_name? flags a control byte before the colon and nothing else" do
    clean = [
      "From: a@b.test\r\nSubject: hi\r\n\r\nbody",
      "From : a@b.test\r\nSubject\t: hi\r\n\r\nbody",                 # obs-syntax WSP
      "Subject\r\n : folded before the colon\r\n\r\nbody",              # a fold is WSP
      "Subject: \e$B raw iso-2022-jp \e(B\v\f\x01\r\n\r\nbody",         # controls in a VALUE
      "Subject: hi\r\n\r\nX-Original-To\v: in the body\r\n",            # body, not header
      "From someone Mon Jan  1 00:00:00 2024\r\nFrom: a@b.test\r\n\r\n", # mbox line: spaces, no controls
      "a line with no colon and a \v control\r\nFrom: a@b.test\r\n\r\n",
      "Caf\xC3\xA9: 8-bit name, not a control\r\n\r\nbody",
      ""
    ]
    clean.each { |data| assert_not HeaderField.control_in_name?(data), data.inspect }

    hostile = [ "\v", "\f", "\x00", "\x01", "\x08", "\x0e", "\x1b", "\x1f", "\x7f" ].flat_map do |byte|
      [ "From: a@b.test\r\nX-Original-To#{byte}: v@local.test\r\n\r\nbody",
        "From: a@b.test\r\n#{byte}From: c@d.test\r\n\r\nbody",
        "From: a@b.test\r\nFr#{byte}om: c@d.test\r\n\r\nbody",
        "From#{byte} : a@b.test\r\n\r\nbody" ]
    end
    hostile.each { |data| assert HeaderField.control_in_name?(data), data.inspect }
  end

  test "block is the header as sent: through the last field's CRLF, empty for an all-body message" do
    assert_equal "A: 1\r\nB: 2\r\n", HeaderField.block("A: 1\r\nB: 2\r\n\r\nbody\r\n\r\nmore")
    assert_equal "A: 1\r\nB: 2\r\n", HeaderField.block("A: 1\r\nB: 2\r\n"), "no empty line: all header"
    assert_equal "", HeaderField.block("\r\nbody: text\r\n\r\nmore")
    assert_equal [], HeaderField.fields("\r\nX-Original-To\v: a body line\r\n\r\nmore")
    assert_not HeaderField.control_in_name?("\r\nX-Original-To\v: a body line\r\n\r\nmore")
    assert_equal Encoding::BINARY, HeaderField.block("A: \u00e9\r\n\r\n").encoding
  end

  test "works on bytes: invalid UTF-8 neither raises nor hides a field" do
    data = "Subject: \xff\xfe\r\nFrom\v: a@b.test\r\n\r\n\xff".dup.force_encoding(Encoding::UTF_8)
    assert HeaderField.control_in_name?(data)
    assert_equal 2, HeaderField.fields(data).size
  end
end
