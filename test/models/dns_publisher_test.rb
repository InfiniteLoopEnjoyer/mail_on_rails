require "test_helper"

class DnsPublisherTest < ActiveSupport::TestCase
  # In-memory Cloudflare stand-in: canned records keyed by [type, name],
  # captures create/update calls.
  class FakeCloudflare
    attr_reader :created, :updated

    def initialize(records = {})
      @records = records
      @created = []
      @updated = []
    end

    def zone_id(_name) = "zone-1"
    def records(_zone, type:, name:) = @records.fetch([ type, name ], [])
    def create_record(_zone, attrs) = @created << attrs
    def update_record(_zone, record_id, attrs) = @updated << [ record_id, attrs ]
  end

  setup do
    ENV["SMTP_HELO_HOST"] = "mail.host.test"
    @domain = Domain.create!(name: "example.com")
  end

  teardown do
    ENV.delete("SMTP_HELO_HOST")
  end

  def publish(records = {})
    client = FakeCloudflare.new(records)
    result = DnsPublisher.publish!(@domain, client: client)
    [ result, client ]
  end

  # RFC 1035 presentation form, as DnsPublisher sends TXT content.
  def quoted(content)
    content.scan(/.{1,255}/m).map { |part| %("#{part}") }.join(" ")
  end

  test "an empty zone gets all four records created" do
    result, client = publish

    assert_equal 4, client.created.size
    by_type = client.created.group_by { |r| r[:type] }
    assert_equal "mail.host.test", by_type["MX"].first[:content]
    assert_equal 10, by_type["MX"].first[:priority]
    contents = by_type["TXT"].map { |r| r[:content] }
    assert_includes contents, '"v=spf1 mx -all"'
    assert_includes contents, quoted(@domain.dkim_txt_value)
    assert_includes contents, '"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'
    assert_equal 4, result.actions.size
    assert_empty client.updated
  end

  test "a fully published zone changes nothing" do
    result, client = publish(
      [ "MX", "example.com" ] => [ { "content" => "mail.host.test" } ],
      [ "TXT", "example.com" ] => [ { "content" => "v=spf1 mx -all" } ],
      [ "TXT", @domain.dkim_txt_name ] => [ { "id" => "r1", "content" => @domain.dkim_txt_value } ],
      [ "TXT", "_dmarc.example.com" ] => [ { "content" => "v=DMARC1; p=reject" } ]
    )

    assert_empty client.created
    assert_empty client.updated
    assert_empty result.actions
    assert_equal 4, result.skipped.size
  end

  test "existing MX pointing elsewhere is never overwritten" do
    result, client = publish([ "MX", "example.com" ] => [ { "content" => "route.mx.cloudflare.net" } ])

    assert client.created.none? { |r| r[:type] == "MX" }
    assert result.skipped.any? { |s| s.include?("points elsewhere") && s.include?("route.mx.cloudflare.net") }
  end

  test "an existing SPF or DMARC policy is respected, even when different from ours" do
    result, client = publish(
      [ "TXT", "example.com" ] => [ { "content" => "\"v=spf1 ip4:203.0.113.9 -all\"" } ],
      [ "TXT", "_dmarc.example.com" ] => [ { "content" => "v=DMARC1; p=quarantine; rua=mailto:elsewhere@other.test" } ]
    )

    contents = client.created.map { |r| r[:content] }
    assert contents.none? { |c| c.start_with?("v=spf1") }, "must not add a second SPF"
    assert contents.none? { |c| c.start_with?("v=DMARC1") }, "must not touch an existing DMARC"
    assert_equal 2, result.skipped.grep(/SPF|DMARC/).size
  end

  test "a matching DKIM TXT stored in quoted multi-string form is left alone" do
    result, client = publish([ "TXT", @domain.dkim_txt_name ] => [ { "id" => "r1", "content" => quoted(@domain.dkim_txt_value) } ])

    assert_empty client.updated
    assert result.skipped.any? { |s| s.include?("DKIM TXT already matches") }
  end

  test "a mismatched DKIM TXT is updated in place" do
    other = "v=DKIM1; k=rsa; p=#{Base64.strict_encode64(OpenSSL::PKey::RSA.new(2048).public_to_der)}"
    result, client = publish([ "TXT", @domain.dkim_txt_name ] => [ { "id" => "rec-9", "content" => other } ])

    assert_equal 1, client.updated.size
    record_id, attrs = client.updated.first
    assert_equal "rec-9", record_id
    assert_equal quoted(@domain.dkim_txt_value), attrs[:content]
    assert result.actions.any? { |a| a.include?("updated DKIM") }
  end

  test "no local DKIM key means the DKIM record is skipped" do
    @domain.update!(dkim_private_key: nil)
    result, client = publish

    assert client.created.none? { |r| r[:name].include?("_domainkey") }
    assert result.skipped.any? { |s| s.include?("no signing key") }
  end

  test "requires SMTP_HELO_HOST" do
    ENV.delete("SMTP_HELO_HOST")
    assert_raises(CloudflareDns::Error) { publish }
  end
end
