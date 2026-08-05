require "test_helper"

class SessionsControllerTest < ActionDispatch::IntegrationTest
  setup { @user = User.take }

  test "new" do
    get new_session_path
    assert_response :success
  end

  test "create with valid credentials" do
    post session_path, params: { email_address: @user.email_address, password: "password" }

    assert_redirected_to root_path
    assert cookies[:session_id]
  end

  test "create with invalid credentials" do
    post session_path, params: { email_address: @user.email_address, password: "wrong" }

    assert_redirected_to new_session_path
    assert_nil cookies[:session_id]
  end

  # The web login is rate limited by Rails' own rate_limit; this is the
  # audit trail, so failures here land in the same log as IMAP and SMTP.
  test "a failed sign-in is recorded in the attempt log" do
    post session_path, params: { email_address: @user.email_address, password: "wrong" }

    attempt = AuthAttempt.sole
    assert_equal "web", attempt.source
    assert_equal @user.email_address, attempt.username
    assert attempt.account_exists, "this login does exist"
  end

  test "a successful sign-in is not recorded" do
    post session_path, params: { email_address: @user.email_address, password: "password" }
    assert_equal 0, AuthAttempt.count
  end

  # BannedIp covers the web surface too: even the right password is not
  # looked at from a banned address.
  test "a banned address cannot sign in with valid credentials" do
    BannedIp.create!(cidr: "127.0.0.1")

    post session_path, params: { email_address: @user.email_address, password: "password" }

    assert_redirected_to new_session_path
    assert_nil cookies[:session_id]
    attempt = AuthAttempt.sole
    assert_equal "web", attempt.source
    assert_equal "throttled", attempt.outcome
  end

  test "destroy" do
    sign_in_as(User.take)

    delete session_path

    assert_redirected_to new_session_path
    assert_empty cookies[:session_id]
  end
end
