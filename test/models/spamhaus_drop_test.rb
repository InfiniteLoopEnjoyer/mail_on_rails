require "test_helper"

class SpamhausDropTest < ActiveSupport::TestCase
  # A fetch stand-in serving one fake DROP file per URL, in Spamhaus's
  # newline-delimited JSON shape (metadata lines carry no "cidr" key).
  def refresh(v4_cidrs, v6_cidrs = [])
    bodies = {
      "https://www.spamhaus.org/drop/drop_v4.json" => body_for(v4_cidrs),
      "https://www.spamhaus.org/drop/drop_v6.json" => body_for(v6_cidrs)
    }
    SpamhausDrop.refresh!(fetch: ->(url) { bodies.fetch(url) })
  end

  def body_for(cidrs)
    lines = cidrs.map { |cidr| { cidr: cidr, sblid: "SBL0" }.to_json }
    lines << { type: "metadata", timestamp: 1 }.to_json
    lines.join("\n")
  end

  test "imports the fetched netblocks as spamhaus_drop rows" do
    refresh(%w[203.0.113.0/24 198.51.100.0/24], %w[2001:db8::/32])

    assert_equal %w[198.51.100.0/24 203.0.113.0/24 2001:db8::/32],
                 BannedIp.spamhaus_drop.pluck(:cidr).sort_by { |c| [ c.include?(":") ? 1 : 0, c ] }
  end

  test "a refresh drops delisted netblocks and keeps manual bans" do
    BannedIp.create!(cidr: "192.0.2.0/24", note: "mine")
    refresh(%w[203.0.113.0/24])

    refresh(%w[198.51.100.0/24])

    assert_equal %w[198.51.100.0/24], BannedIp.spamhaus_drop.pluck(:cidr)
    assert_equal %w[192.0.2.0/24], BannedIp.manual.pluck(:cidr)
  end

  test "a manually banned netblock stays manual with its note" do
    BannedIp.create!(cidr: "203.0.113.0/24", note: "beat Spamhaus to it")

    refresh(%w[203.0.113.0/24])

    ban = BannedIp.sole
    assert_equal "manual", ban.source
    assert_equal "beat Spamhaus to it", ban.note
  end

  test "an empty parse raises instead of wiping the imported rows" do
    refresh(%w[203.0.113.0/24])

    assert_raises(RuntimeError) { refresh([]) }
    assert_equal %w[203.0.113.0/24], BannedIp.spamhaus_drop.pluck(:cidr)
  end

  test "a failed fetch propagates without touching rows" do
    refresh(%w[203.0.113.0/24])

    assert_raises(RuntimeError) do
      SpamhausDrop.refresh!(fetch: ->(_url) { raise "boom" })
    end
    assert_equal %w[203.0.113.0/24], BannedIp.spamhaus_drop.pluck(:cidr)
  end

  test "unparseable entries are skipped, not fatal" do
    refresh([ "203.0.113.0/24", "bogus" ])

    assert_equal %w[203.0.113.0/24], BannedIp.spamhaus_drop.pluck(:cidr)
  end

  test "the file is rewritten after a refresh" do
    Dir.mktmpdir do |dir|
      ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"] = File.join(dir, "banned_ips")
      refresh(%w[203.0.113.0/24])

      assert_equal %w[203.0.113.0/24], BannedIpsFile.current
    ensure
      ENV.delete("MAIL_ON_RAILS_BANNED_IPS_FILE")
    end
  end
end
