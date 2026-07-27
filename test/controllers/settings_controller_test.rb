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
      assert_select "span", text: "in sync with database"
      assert_select "pre", text: /settings@example\.test/

      # Drift both ways: a file entry with no row, a row not in the file.
      File.write(ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"], "ghost@example.test\n")
      get settings_url
      assert_select "span", text: "drifted from database"
      assert_select "p", text: /exim rejects these\):\s*#{Regexp.escape(account.email)}/
      assert_select "p", text: /exim still accepts these\):\s*ghost@example\.test/
    end
  end

  test "flags a missing file" do
    ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"] = "/nonexistent/local_domains"
    get settings_url
    assert_select "span", text: "file missing - exim defers all inbound"
  end
end
