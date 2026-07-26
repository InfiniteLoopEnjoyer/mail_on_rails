require "test_helper"

class DomainTest < ActiveSupport::TestCase
  setup do
    @exim_dir = Dir.mktmpdir
    @exim_file = File.join(@exim_dir, "local_domains")
    ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"] = @exim_file
  end

  teardown do
    ENV.delete("MAIL_ON_RAILS_EXIM_DOMAINS_FILE")
    FileUtils.remove_entry(@exim_dir)
  end

  test "normalizes the name" do
    domain = Domain.create!(name: "  Example.COM.  ")
    assert_equal "example.com", domain.name
  end

  test "rejects names that are not plain FQDNs" do
    [ "", "nodots", "exim:list", "bad domain.com", "*.example.com", "-x.example.com" ].each do |name|
      assert_not Domain.new(name: name).valid?, "#{name.inspect} should be invalid"
    end
  end

  test "create mints an encrypted DKIM key and writes the exim file" do
    domain = Domain.create!(name: "example.com")

    assert_instance_of OpenSSL::PKey::RSA, OpenSSL::PKey.read(domain.dkim_private_key)
    assert_equal "example.com\n", File.read(@exim_file)
    assert domain.synced_to_exim?
    assert_match(/\Av=DKIM1; k=rsa; p=[A-Za-z0-9+\/]+=*\z/, domain.dkim_key.txt_value)
    # Stored encrypted: the raw column bytes must not contain the PEM.
    raw = Domain.connection.select_value("SELECT dkim_private_key FROM domains WHERE id = #{domain.id}")
    assert_not_includes raw.to_s, "PRIVATE KEY"
  end

  test "create keeps a key supplied up front (imports) instead of minting" do
    pem = DkimKey.generate_pem
    domain = Domain.create!(name: "example.com", dkim_private_key: pem)
    assert_equal pem, domain.dkim_private_key
  end

  test "the key dies with the domain; re-creating mints a fresh one" do
    domain = Domain.create!(name: "example.com")
    original = domain.dkim_private_key

    domain.destroy!
    assert_equal "\n", File.read(@exim_file)

    recreated = Domain.create!(name: "example.com")
    assert recreated.dkim_private_key.present?
    assert_not_equal original, recreated.dkim_private_key
  end

  test "sync refuses an empty list unless forced" do
    assert_raises(EximLocalDomains::Error) { EximLocalDomains.sync! }
    assert_equal :written, EximLocalDomains.sync!(force_empty: true)
    assert_equal "\n", File.read(@exim_file)
  end

  test "sync writes all domains sorted, world-readable" do
    Domain.create!(name: "zeta.example.com")
    Domain.create!(name: "alpha.example.com")
    assert_equal "alpha.example.com\nzeta.example.com\n", File.read(@exim_file)
    assert_equal 0o644, File.stat(@exim_file).mode & 0o777
  end

  test "sync is a no-op without the env var" do
    ENV.delete("MAIL_ON_RAILS_EXIM_DOMAINS_FILE")
    assert_equal :skipped, EximLocalDomains.sync!
  end
end
