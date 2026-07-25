require "test_helper"

class DomainTest < ActiveSupport::TestCase
  setup do
    @dkim_dir = Dir.mktmpdir
    @exim_dir = Dir.mktmpdir
    @exim_file = File.join(@exim_dir, "local_domains")
    ENV["MAIL_ON_RAILS_DKIM_DIR"] = @dkim_dir
    ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"] = @exim_file
  end

  teardown do
    ENV.delete("MAIL_ON_RAILS_DKIM_DIR")
    ENV.delete("MAIL_ON_RAILS_EXIM_DOMAINS_FILE")
    FileUtils.remove_entry(@dkim_dir)
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

  test "create generates a DKIM key and writes the exim file" do
    domain = Domain.create!(name: "example.com")
    key_path = File.join(@dkim_dir, "example.com.pem")

    assert File.exist?(key_path)
    assert_instance_of OpenSSL::PKey::RSA, OpenSSL::PKey.read(File.read(key_path))
    assert_equal "example.com\n", File.read(@exim_file)
    assert domain.synced_to_exim?
    assert_match(/\Av=DKIM1; k=rsa; p=[A-Za-z0-9+\/]+=*\z/, domain.dkim_key.txt_value)
  end

  test "create never overwrites an existing DKIM key" do
    key_path = File.join(@dkim_dir, "example.com.pem")
    existing = OpenSSL::PKey::RSA.new(2048).to_pem
    File.write(key_path, existing)

    Domain.create!(name: "example.com")
    assert_equal existing, File.read(key_path)
  end

  test "destroy retires the key, and re-creating restores it" do
    domain = Domain.create!(name: "example.com")
    key_path = File.join(@dkim_dir, "example.com.pem")
    original = File.read(key_path)

    domain.destroy!
    assert_not File.exist?(key_path)
    assert File.exist?("#{key_path}.disabled")
    assert_equal "\n", File.read(@exim_file)

    Domain.create!(name: "example.com")
    assert_equal original, File.read(key_path)
    assert_not File.exist?("#{key_path}.disabled")
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
