require "test_helper"

class PasswordsControllerTest < ActionDispatch::IntegrationTest
  setup { @user = User.take }

  test "new" do
    get new_password_path
    assert_response :success
  end

  test "create" do
    post passwords_path, params: { email_address: @user.email_address }
    assert_enqueued_email_with PasswordsMailer, :reset, args: [ @user ]
    assert_redirected_to new_session_path

    follow_redirect!
    assert_notice "reset instructions sent"
  end

  test "create for an unknown user redirects but sends no mail" do
    post passwords_path, params: { email_address: "missing-user@example.com" }
    assert_enqueued_emails 0
    assert_redirected_to new_session_path

    follow_redirect!
    assert_notice "reset instructions sent"
  end

  test "edit" do
    get edit_password_path(@user.password_reset_token)
    assert_response :success
  end

  test "edit with invalid password reset token" do
    get edit_password_path("invalid token")
    assert_redirected_to new_password_path

    follow_redirect!
    assert_notice "reset link is invalid"
  end

  test "update generates a password, shows it once and destroys all sessions" do
    @user.sessions.create!

    assert_changes -> { @user.reload.password_digest } do
      put password_path(@user.password_reset_token)
      assert_response :success
    end

    plaintext = extract_generated_password
    assert @user.reload.authenticate(plaintext)
    assert_empty @user.sessions
  end

  test "reset token is single-use" do
    token = @user.password_reset_token
    put password_path(token)
    assert_response :success

    assert_no_changes -> { @user.reload.password_digest } do
      put password_path(token)
      assert_redirected_to new_password_path
    end

    follow_redirect!
    assert_notice "reset link is invalid"
  end

  private
    def assert_notice(text)
      assert_select "div", /#{text}/
    end
end
