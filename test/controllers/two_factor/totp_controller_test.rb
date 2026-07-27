require "test_helper"

class TwoFactor::TotpControllerTest < ActionDispatch::IntegrationTest
  setup { @user = users(:one) }

  test "requires authentication" do
    get new_two_factor_totp_path
    assert_redirected_to new_session_path
  end

  test "enable with a valid code, then disable" do
    sign_in_as(@user)

    get new_two_factor_totp_path
    assert_response :success
    secret = css_select("code").first.text

    post two_factor_totp_path, params: { code: ROTP::TOTP.new(secret).now }
    assert_redirected_to security_path
    assert @user.reload.otp_enabled?
    assert_equal secret, @user.otp_secret

    delete two_factor_totp_path
    assert_redirected_to security_path
    assert_not @user.reload.otp_enabled?
  end

  test "wrong confirmation code does not enable" do
    sign_in_as(@user)
    get new_two_factor_totp_path

    post two_factor_totp_path, params: { code: "000000" }

    assert_redirected_to new_two_factor_totp_path
    assert_not @user.reload.otp_enabled?
  end

  test "confirming keeps the same secret across re-renders" do
    sign_in_as(@user)
    get new_two_factor_totp_path
    secret = css_select("code").first.text

    get new_two_factor_totp_path
    assert_equal secret, css_select("code").first.text, "re-render must not rotate the pending secret"
  end
end
