require "test_helper"

class UsersControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:one)
    sign_in_as @user
  end

  test "requires authentication" do
    sign_out
    get users_url
    assert_redirected_to new_session_url
  end

  test "index lists users" do
    get users_url
    assert_response :success
    assert_select ".primary", text: @user.email_address
    assert_select "turbo-cable-stream-source", 1
  end

  test "creates a user with a generated password shown once" do
    assert_difference "User.count", 1 do
      post users_url, params: { user: { email_address: "new@example.com" } }
    end
    user = User.find_by(email_address: "new@example.com")
    assert_redirected_to edit_user_url(user)

    follow_redirect!
    plaintext = extract_generated_password
    assert user.authenticate(plaintext)

    get edit_user_url(user)
    assert_not_includes response.body, plaintext
  end

  test "editing your own account shows passkeys and totp state" do
    @user.webauthn_credentials.create!(external_id: "abc", public_key: "pk", nickname: "My YubiKey")

    get edit_user_url(@user)

    assert_response :success
    assert_match "My YubiKey", response.body
    assert_match "Set up authenticator app", response.body
  end

  test "editing another user hides the two-factor sections" do
    get edit_user_url(users(:two))

    assert_response :success
    assert_no_match "Set up authenticator app", response.body
    assert_no_match "Register passkey", response.body
  end

  test "rejects a duplicate email address" do
    assert_no_difference "User.count" do
      post users_url, params: { user: { email_address: @user.email_address } }
    end
    assert_response :unprocessable_entity
  end

  test "update ignores password params" do
    other = users(:two)
    patch user_url(other), params: { user: { email_address: "renamed@example.com", password: "sneaky" } }
    assert_redirected_to users_url
    other.reload
    assert_equal "renamed@example.com", other.email_address
    assert other.authenticate("password")
    assert_not other.authenticate("sneaky")
  end

  test "generate_password for another user rotates their password and destroys their sessions" do
    other = users(:two)
    other.sessions.create!

    post generate_password_user_url(other), headers: { "Accept" => "text/vnd.turbo-stream.html" }
    assert_response :success
    assert_select "turbo-stream[action=replace][target=password-generator]"

    plaintext = extract_generated_password
    other.reload
    assert other.authenticate(plaintext)
    assert_not other.authenticate("password")
    assert_empty other.sessions

    get edit_user_url(other)
    assert_not_includes response.body, plaintext
  end

  test "generate_password for yourself keeps the current session" do
    @user.sessions.create!

    post generate_password_user_url(@user), headers: { "Accept" => "text/vnd.turbo-stream.html" }
    assert_response :success
    assert_equal 1, @user.sessions.count

    get users_url
    assert_response :success
  end

  test "destroys a user" do
    assert_difference "User.count", -1 do
      delete user_url(users(:two))
    end
    assert_redirected_to users_url
  end

  test "destroying yourself signs you out" do
    assert_difference "User.count", -1 do
      delete user_url(@user)
    end
    assert_redirected_to new_session_url
    assert_nil User.find_by(id: @user.id)

    get users_url
    assert_redirected_to new_session_url
  end
end
