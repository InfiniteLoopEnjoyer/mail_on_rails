# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/sender_auth"

# SenderAuth::FromHeader replaced the mail gem for From: domain extraction
# (the gem is not Ractor-safe, and sessions run inside worker Ractors).
# Mainstream shapes are parity-checked against the mail gem - still a
# development dependency - so the hand-rolled parser can't quietly drift
# from the reference; hostile/exotic shapes get direct expectations.
class FromHeaderTest < Minitest::Test
  FromHeader = MailOnRails::SenderAuth::FromHeader

  # Mirrors the previous Mail-gem-based implementation, as the reference.
  def mail_gem_domain(data)
    require "mail"
    header_block = data.to_s.gsub(/(?<!\r)\n/, "\r\n").partition("\r\n\r\n").first
    mail = Mail.read_from_string(header_block + "\r\n\r\n")
    addresses = Array(mail.from)
    return nil unless addresses.size == 1

    addresses.first.to_s.split("@").last&.downcase
  rescue StandardError
    nil
  end

  PARITY = [
    "From: alice@example.com\r\n\r\nbody",
    "From: Alice Wonder <alice@Example.COM>\r\n\r\nbody",
    "From: \"Alice @ Home\" <alice@example.com>\r\n\r\nbody",
    "From: Alice (on holiday) <alice@example.com>\r\n\r\nbody",
    "From: alice@example.com, bob@other.example\r\n\r\nbody",
    "From: Alice\r\n <alice@example.com>\r\n\r\nbody",
    "Subject: hi\r\nFrom: alice@example.com\r\nTo: x@y.z\r\n\r\nbody",
    "Subject: no from at all\r\n\r\nbody",
    "From: alice@sub.example.co.uk\n\nbare lf body",
    "FROM:alice@example.com\r\n\r\ncase and no space",
    "From: =?UTF-8?B?QWxpY2U=?= <alice@example.com>\r\n\r\nbody"
  ].freeze

  test "matches the mail gem on mainstream headers" do
    PARITY.each do |data|
      expected = mail_gem_domain(data)
      actual = FromHeader.domain(data)
      if expected.nil?
        assert_nil actual, "input: #{data.inspect}"
      else
        assert_equal expected, actual, "input: #{data.inspect}"
      end
    end
  end

  EDGES = {
    # Deliberate divergence from the mail gem: it lets the LAST of several
    # From: headers win, which is exactly the duplicate-header trick DMARC
    # evasion uses. No verdict subject is the safe answer (-> permerror).
    "From: alice@example.com\r\nFrom: bob@other.example\r\n\r\nbody" => nil,
    # Deliberate divergence: the old split("@").last approach returned the
    # whole token when there was no @ at all - not a domain.
    "From: not-an-address\r\n\r\nbody" => nil,
    # group syntax has no DMARC verdict
    "From: undisclosed-recipients:;\r\n\r\nbody" => nil,
    # obsolete source route inside the angle-addr
    "From: <@relay1,@relay2:alice@example.com>\r\n\r\nbody" => "example.com",
    # quoted local part containing @
    "From: \"real@fake\"@example.com\r\n\r\nbody" => "example.com",
    # display name containing an escaped quote
    "From: \"A \\\" B\" <alice@example.com>\r\n\r\nbody" => "example.com",
    # nested comment
    "From: Alice ((very) nested) <alice@example.com>\r\n\r\nbody" => "example.com",
    # unbalanced quoting never parses
    "From: \"broken <alice@example.com>\r\n\r\nbody" => nil,
    "From: <alice@example.com\r\n\r\nbody" => nil,
    # two angle-addrs is invalid
    "From: <a@b.example> <c@d.example>\r\n\r\nbody" => nil,
    # whitespace inside the domain is malformed
    "From: alice@exa mple.com\r\n\r\nbody" => nil,
    # domain literals have no DMARC domain
    "From: alice@[192.0.2.1]\r\n\r\nbody" => nil,
    # From: only in the body must not count
    "Subject: x\r\n\r\nFrom: alice@example.com\r\n" => nil,
    # empty and absent input
    "" => nil
  }.freeze

  test "hostile and exotic shapes" do
    EDGES.each do |data, expected|
      actual = FromHeader.domain(data)
      if expected.nil?
        assert_nil actual, "input: #{data.inspect}"
      else
        assert_equal expected, actual, "input: #{data.inspect}"
      end
    end
  end

  # The Mail gem ends a field name with Ruby's rstrip, which drops NUL, TAB,
  # LF, VT, FF, CR and SP - so "From\v:" is a From to the parser the
  # mailroom and the reader's UI use, and has to be one here. With only
  # [ \t]* tolerated the gate saw a single From (the attacker's own,
  # DMARC-passing domain) while the stored and displayed sender was the
  # second one.
  GAPS = [ "\v", "\f", " ", "\t", " \t", "\x00", "\x01", "\x1f", "\x7f", "\xC2\xA0".b, "\v \f" ].freeze

  test "a second From hidden behind a control byte before the colon is still a second From" do
    GAPS.each do |gap|
      data = "From: attacker@evil.test\r\nFrom#{gap}: ceo@bank.test\r\nSubject: x\r\n\r\nbody\r\n".b
      assert_nil FromHeader.domain(data), "gap #{gap.inspect} hid the second From from the single-From gate"
      assert_equal %w[attacker@evil.test ceo@bank.test], FromHeader.addresses(data), "gap #{gap.inspect}"
    end
  end

  test "a lone From with a gap before its colon is read, as the Mail gem reads it" do
    require "mail"
    [ "\v", "\f", " ", "\t" ].each do |gap|
      data = "Subject: x\r\nFrom#{gap}: ceo@bank.test\r\n\r\nbody\r\n".b
      assert_equal [ "ceo@bank.test" ], Mail.read_from_string(data).from, "reference changed for #{gap.inspect}"
      assert_equal "bank.test", FromHeader.domain(data), "gap #{gap.inspect}"
      assert_equal [ "ceo@bank.test" ], FromHeader.addresses(data), "gap #{gap.inspect}"
    end
  end

  test "Sender is matched through the same gap" do
    data = "From: me@mine.test\r\nSender\f: other@else.test\r\n\r\nbody\r\n".b
    assert_equal [ "other@else.test" ], FromHeader.addresses(data, field: "sender")
  end

  test "a longer field name is not mistaken for From" do
    data = "From-Extra: x@y.test\r\nFrom: a@example.com\r\n\r\nbody\r\n".b
    assert_equal "example.com", FromHeader.domain(data)
  end

  test "from_domain delegates and never raises" do
    assert_equal "example.com", MailOnRails::SenderAuth.from_domain("From: a@Example.Com\r\n\r\nx")
    assert_nil MailOnRails::SenderAuth.from_domain(nil)
    assert_nil MailOnRails::SenderAuth.from_domain("\xff\xfe garbage".b)
  end
end
