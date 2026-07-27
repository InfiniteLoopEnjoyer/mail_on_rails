require "test_helper"
require "tmpdir"

class EximLocalRecipientsTest < ActiveSupport::TestCase
  setup do
    @dir = Dir.mktmpdir
    @path = File.join(@dir, "local_recipients")
    ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"] = @path
  end

  teardown do
    ENV.delete("MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE")
    FileUtils.remove_entry(@dir)
  end

  test "no-op without the env var" do
    ENV.delete("MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE")
    assert_equal :skipped, EximLocalRecipients.sync!
    assert_equal [], EximLocalRecipients.current
  end

  test "writes one normalized address per line, sorted, world-readable" do
    EmailAccount.create!(email: " B@Example.test ", password: "secret-pass-123")
    EmailAccount.create!(email: "a@example.test", password: "secret-pass-123")

    assert_equal :written, EximLocalRecipients.sync!
    assert_equal %w[a@example.test b@example.test], File.readlines(@path, chomp: true)
    assert_equal %w[a@example.test b@example.test], EximLocalRecipients.current
    assert_equal 0o644, File.stat(@path).mode & 0o777
  end

  test "aliases are interleaved with account addresses" do
    account = EmailAccount.create!(email: "b@example.test", password: "secret-pass-123")
    account.email_aliases.create!(email: "a@example.test")
    account.email_aliases.create!(email: "c@example.test")

    assert_equal %w[a@example.test b@example.test c@example.test], EximLocalRecipients.current
  end

  test "an empty account table writes an empty list without force" do
    assert_equal :written, EximLocalRecipients.sync!
    assert_equal [], EximLocalRecipients.current
  end

  test "raises when the directory is not writable" do
    ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"] = "/nonexistent/local_recipients"
    assert_raises(EximLocalRecipients::Error) { EximLocalRecipients.sync! }
  end

  test "account create, rename, and destroy keep the file in step" do
    account = EmailAccount.create!(email: "sync@example.test", password: "secret-pass-123")
    assert_includes EximLocalRecipients.current, "sync@example.test"

    account.update!(email: "renamed@example.test")
    assert_includes EximLocalRecipients.current, "renamed@example.test"
    assert_not_includes EximLocalRecipients.current, "sync@example.test"

    account.destroy!
    assert_not_includes EximLocalRecipients.current, "renamed@example.test"
  end
end
