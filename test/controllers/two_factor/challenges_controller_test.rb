require "test_helper"
require "webauthn/fake_client"

class TwoFactor::ChallengesControllerTest < ActionDispatch::IntegrationTest
  ORIGIN = "http://www.example.com"

  setup do
    @user = users(:one)
    @user.update!(otp_secret: ROTP::Base32.random)
  end

  test "password login with a second factor parks the user on the challenge" do
    post session_path, params: { email_address: @user.email_address, password: "password" }

    assert_redirected_to new_two_factor_challenge_path
    assert_nil cookies[:session_id].presence, "no session until the second factor passes"

    get new_two_factor_challenge_path
    assert_response :success
  end

  test "valid TOTP code completes sign-in; replaying it does not" do
    start_challenge
    code = ROTP::TOTP.new(@user.otp_secret).now

    post totp_two_factor_challenge_path, params: { code: code }
    assert_redirected_to root_url
    assert cookies[:session_id].present?

    delete session_path
    start_challenge
    post totp_two_factor_challenge_path, params: { code: code }
    assert_redirected_to new_two_factor_challenge_path
    assert_nil cookies[:session_id].presence
  end

  test "wrong TOTP code is rejected" do
    start_challenge

    post totp_two_factor_challenge_path, params: { code: "000000" }

    assert_redirected_to new_two_factor_challenge_path
    assert_nil cookies[:session_id].presence
  end

  test "pending sign-in expires after the grace period" do
    start_challenge

    travel 6.minutes do
      post totp_two_factor_challenge_path, params: { code: ROTP::TOTP.new(@user.otp_secret).now }
      assert_redirected_to new_session_path
      assert_nil cookies[:session_id].presence
    end
  end

  test "challenge without a pending sign-in redirects to login" do
    get new_two_factor_challenge_path
    assert_redirected_to new_session_path
  end

  test "passkey assertion completes sign-in" do
    client = register_passkey

    start_challenge
    post webauthn_options_two_factor_challenge_path, as: :json
    assert_response :success
    challenge = response.parsed_body["challenge"]

    post webauthn_two_factor_challenge_path,
      params: { credential: client.get(challenge: challenge) }, as: :json

    assert_response :success
    assert_equal root_url, response.parsed_body["location"]
    assert cookies[:session_id].present?
  end

  test "passkey assertion with a stale challenge is rejected" do
    client = register_passkey

    start_challenge
    post webauthn_options_two_factor_challenge_path, as: :json
    fake_challenge = WebAuthn.standard_encoder.encode(SecureRandom.random_bytes(32))

    post webauthn_two_factor_challenge_path,
      params: { credential: client.get(challenge: fake_challenge) }, as: :json

    assert_response :unprocessable_entity
    assert_nil cookies[:session_id].presence
  end

  private
    def start_challenge
      post session_path, params: { email_address: @user.email_address, password: "password" }
      assert_redirected_to new_two_factor_challenge_path
    end

    # Enrolls a passkey through the real endpoints while signed in, then
    # signs out. Returns the fake client holding the credential.
    def register_passkey
      client = WebAuthn::FakeClient.new(ORIGIN)
      sign_in_as(@user)
      post options_two_factor_passkeys_path, as: :json
      credential = client.create(challenge: response.parsed_body["challenge"])
      post two_factor_passkeys_path, params: { credential: credential, nickname: "Test key" }, as: :json
      assert_response :success
      delete session_path
      client
    end
end
