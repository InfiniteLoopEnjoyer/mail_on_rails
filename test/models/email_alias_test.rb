require "test_helper"
require "tmpdir"

class EmailAliasTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "owner@example.test", password: "secret-pass-123")
  end

  test "normalizes the address like EmailAccount" do
    email_alias = @account.email_aliases.create!(email: " Sales@Example.test ")
    assert_equal "sales@example.test", email_alias.email
  end

  test "requires an address, unique across aliases case-insensitively" do
    assert_not @account.email_aliases.new(email: "").valid?

    @account.email_aliases.create!(email: "info@example.test")
    other = EmailAccount.create!(email: "other@example.test", password: "secret-pass-123")
    assert_not other.email_aliases.new(email: "INFO@example.test").valid?
  end

  test "an alias cannot take an existing account address" do
    email_alias = @account.email_aliases.new(email: "owner@example.test")
    assert_not email_alias.valid?
    assert_includes email_alias.errors[:email], "is already an account address"
  end

  test "an account cannot take an existing alias address" do
    @account.email_aliases.create!(email: "info@example.test")
    account = EmailAccount.new(email: "info@example.test", password: "secret-pass-123")
    assert_not account.valid?
    assert_includes account.errors[:email], "is already in use as an alias"
  end

  test "destroying the account destroys its aliases" do
    @account.email_aliases.create!(email: "info@example.test")
    assert_difference "EmailAlias.count", -1 do
      @account.destroy!
    end
  end

  test "alias create, rename, and destroy keep the exim recipients file in step" do
    Dir.mktmpdir do |dir|
      ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"] = File.join(dir, "local_recipients")

      email_alias = @account.email_aliases.create!(email: "info@example.test")
      assert_equal %w[info@example.test owner@example.test], EximLocalRecipients.current

      email_alias.update!(email: "contact@example.test")
      assert_equal %w[contact@example.test owner@example.test], EximLocalRecipients.current

      email_alias.destroy!
      assert_equal %w[owner@example.test], EximLocalRecipients.current
    ensure
      ENV.delete("MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE")
    end
  end
end
