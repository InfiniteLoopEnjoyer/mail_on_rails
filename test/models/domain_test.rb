require "test_helper"

class DomainTest < ActiveSupport::TestCase
  test "normalizes the name" do
    domain = Domain.create!(name: "  Example.COM.  ")
    assert_equal "example.com", domain.name
  end

  test "rejects names that are not plain FQDNs" do
    [ "", "nodots", "colon:list", "bad domain.com", "*.example.com", "-x.example.com" ].each do |name|
      assert_not Domain.new(name: name).valid?, "#{name.inspect} should be invalid"
    end
  end

  test "create mints an encrypted DKIM key" do
    domain = Domain.create!(name: "example.com")

    assert_instance_of OpenSSL::PKey::RSA, OpenSSL::PKey.read(domain.dkim_private_key)
    assert_match(/\Av=DKIM1; k=rsa; p=[A-Za-z0-9+\/]+=*\z/, domain.dkim_txt_value)
    # Stored encrypted: the raw column bytes must not contain the PEM.
    raw = Domain.connection.select_value("SELECT dkim_private_key FROM domains WHERE id = #{domain.id}")
    assert_not_includes raw.to_s, "PRIVATE KEY"
  end

  test "create keeps a key supplied up front (imports) instead of minting" do
    pem = OpenSSL::PKey::RSA.new(Domain::DKIM_KEY_BITS).to_pem
    domain = Domain.create!(name: "example.com", dkim_private_key: pem)
    assert_equal pem, domain.dkim_private_key
  end

  test "the key dies with the domain; re-creating mints a fresh one" do
    domain = Domain.create!(name: "example.com")
    original = domain.dkim_private_key

    domain.destroy!

    recreated = Domain.create!(name: "example.com")
    assert recreated.dkim_private_key.present?
    assert_not_equal original, recreated.dkim_private_key
  end

  test "create provisions the dmarc reports account" do
    domain = Domain.create!(name: "example.com")

    assert EmailAccount.exists?(email: domain.dmarc_address)
    assert Domain.dmarc_ingestion_address?(domain.dmarc_address)
  end
end
