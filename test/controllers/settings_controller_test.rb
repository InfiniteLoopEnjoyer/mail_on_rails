require "test_helper"
require "tmpdir"

class SettingsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
  end

  teardown do
    ENV.delete("MAIL_ON_RAILS_BANNED_IPS_FILE")
  end

  test "requires authentication" do
    sign_out
    get settings_url
    assert_redirected_to new_session_url
  end

  test "shows the not-configured state without the env var" do
    get settings_url
    assert_response :success
    assert_select "span", text: "MAIL_ON_RAILS_BANNED_IPS_FILE not set"
  end

  test "sync rewrites the banned_ips file from the database" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "banned_ips")
      ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"] = path
      BannedIp.delete_all # bypass callbacks so the file starts stale
      BannedIp.insert_all([ { cidr: "203.0.113.0/24", source: "manual",
                              created_at: Time.current, updated_at: Time.current } ])

      post sync_settings_url(file: "banned_ips")

      assert_redirected_to settings_url
      assert_equal %w[203.0.113.0/24], File.readlines(path, chomp: true)
    end
  end

  test "shows file contents and in-sync/drift against the database" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "banned_ips")
      ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"] = path
      BannedIp.delete_all
      BannedIp.create!(cidr: "203.0.113.0/24", source: "manual")

      get settings_url
      assert_response :success
      assert_select "span", text: "Synced"
      assert_select "pre", text: /203\.0\.113\.0\/24/

      # Drift both ways: a file entry with no row, a row not in the file.
      File.write(path, "198.51.100.0/24\n")
      get settings_url
      assert_select "span", text: "Diverged"
      assert_select "p", text: /not yet enforced\):\s*203\.0\.113\.0\/24/
      assert_select "p", text: /still enforced\):\s*198\.51\.100\.0\/24/
    end
  end

  test "flags a missing file" do
    ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"] = "/nonexistent/banned_ips"
    get settings_url
    assert_select "span", text: "File missing - no bans enforced"
  end

  test "sync without the env var configured warns instead of writing" do
    post sync_settings_url(file: "banned_ips")
    assert_redirected_to settings_url
    assert_match(/is not set/, flash[:alert])
  end

  test "sync of an unknown file 404s" do
    post sync_settings_url(file: "nope")
    assert_response :not_found
  end

  # -- trash retention -------------------------------------------------------

  test "shows the trash retention form with the current value" do
    get settings_url
    assert_select "input[name='trash_retention_days'][value='30']"

    Setting.trash_retention_days = 7
    get settings_url
    assert_select "input[name='trash_retention_days'][value='7']"
  end

  test "update saves the trash retention" do
    patch settings_url, params: { trash_retention_days: "45" }
    assert_redirected_to settings_url
    assert_equal "Trash retention set to 45 days.", flash[:notice]
    assert_equal 45, Setting.trash_retention_days
  end

  test "update rejects junk and non-positive retention values" do
    [ "soon", "0", "-3", "" ].each do |bad|
      patch settings_url, params: { trash_retention_days: bad }
      assert_redirected_to settings_url
      assert_match(/whole number of days/, flash[:alert])
      assert_equal 30, Setting.trash_retention_days
    end
  end
end
