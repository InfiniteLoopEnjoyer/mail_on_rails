require "test_helper"

class SecurityControllerTest < ActionDispatch::IntegrationTest
  test "requires authentication" do
    get security_path
    assert_redirected_to new_session_path
  end

  test "lists the user's passkeys and totp state" do
    user = users(:one)
    user.webauthn_credentials.create!(external_id: "abc", public_key: "pk", nickname: "My YubiKey")
    sign_in_as(user)

    get security_path

    assert_response :success
    assert_match "My YubiKey", response.body
    assert_match "Set up authenticator app", response.body
  end
end
