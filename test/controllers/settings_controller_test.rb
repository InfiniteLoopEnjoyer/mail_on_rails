require "test_helper"
require "tmpdir"

class SettingsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
  end

  teardown do
    ENV.delete("MAIL_ON_RAILS_EXIM_DOMAINS_FILE")
    ENV.delete("MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE")
  end

  test "requires authentication" do
    sign_out
    get settings_url
    assert_redirected_to new_session_url
  end

  test "shows the not-configured state without the env vars" do
    get settings_url
    assert_response :success
    assert_select "span", text: "MAIL_ON_RAILS_EXIM_DOMAINS_FILE not set"
    assert_select "span", text: "MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE not set"
  end

  test "shows file contents and in-sync/drift against the database" do
    Dir.mktmpdir do |dir|
      ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"] = File.join(dir, "local_recipients")
      account = EmailAccount.create!(email: "settings@example.test", password: "secret-pass-123")

      get settings_url
      assert_response :success
      assert_select "span", text: "Synced"
      assert_select "pre", text: /settings@example\.test/

      # Drift both ways: a file entry with no row, a row not in the file.
      File.write(ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"], "ghost@example.test\n")
      get settings_url
      assert_select "span", text: "Diverged"
      assert_select "p", text: /exim rejects these\):\s*#{Regexp.escape(account.email)}/
      assert_select "p", text: /exim still accepts these\):\s*ghost@example\.test/
    end
  end

  test "flags a missing file" do
    ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"] = "/nonexistent/local_domains"
    get settings_url
    assert_select "span", text: "file missing - exim defers all inbound"
  end

  test "sync rewrites the recipients file from the database" do
    Dir.mktmpdir do |dir|
      ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"] = File.join(dir, "local_recipients")
      account = EmailAccount.create!(email: "settings@example.test", password: "secret-pass-123")
      File.write(ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"], "ghost@example.test\n")

      post sync_settings_url(file: "recipients")
      assert_redirected_to settings_url
      assert_match(/rewritten from the database/, flash[:notice])
      assert_includes File.read(ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"]), account.email
      refute_includes File.read(ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"]), "ghost@example.test"
    end
  end

  test "sync refuses to write an empty domain list" do
    Dir.mktmpdir do |dir|
      ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"] = File.join(dir, "local_domains")
      Domain.delete_all

      post sync_settings_url(file: "domains")
      assert_redirected_to settings_url
      assert_match(/sync failed/, flash[:alert])
      refute File.exist?(ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"])
    end
  end

  test "sync without the env var configured warns instead of writing" do
    post sync_settings_url(file: "recipients")
    assert_redirected_to settings_url
    assert_match(/is not set/, flash[:alert])
  end

  test "sync of an unknown file 404s" do
    post sync_settings_url(file: "nope")
    assert_response :not_found
  end
end
