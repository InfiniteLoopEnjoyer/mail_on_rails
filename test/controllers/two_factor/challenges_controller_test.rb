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

  # The AuthThrottle account counter must survive the password stage - an
  # attacker who has the password but not the factor cannot refill their
  # budget - and clear only on full sign-in.
  test "account throttle counter clears on completed second factor, not on password success" do
    AuthThrottle.record_failure(ip: "203.0.113.9", email: @user.email_address)

    start_challenge
    assert AuthThrottle.exists?(scope: AuthThrottle::ACCOUNT, key: @user.email_address),
      "password success alone must not clear the counter"

    post totp_two_factor_challenge_path, params: { code: ROTP::TOTP.new(@user.otp_secret).now }

    assert cookies[:session_id].present?
    assert_not AuthThrottle.exists?(scope: AuthThrottle::ACCOUNT, key: @user.email_address)
  end

  # The passkey endpoints are throttled like totp. The test env caches with
  # the null store (which never accumulates), so route the limiter's
  # captured store through a real one for the duration.
  test "webauthn challenge endpoints are rate limited" do
    memory = ActiveSupport::Cache::MemoryStore.new
    store = TwoFactor::ChallengesController.cache_store
    store.define_singleton_method(:increment) { |*args, **kwargs| memory.increment(*args, **kwargs) }

    10.times { post webauthn_options_two_factor_challenge_path, as: :json }
    post webauthn_options_two_factor_challenge_path, as: :json

    assert_response :too_many_requests
    assert_equal "Try again later.", response.parsed_body["error"]

    # Separate counter: the totp budget is untouched by webauthn posts.
    post totp_two_factor_challenge_path, params: { code: "000000" }
    assert_redirected_to new_session_path
  ensure
    store.singleton_class.remove_method(:increment) if store
  end

  test "challenge without a pending sign-in redirects to login" do
    get new_two_factor_challenge_path
    assert_redirected_to new_session_path
  end

  # A wrong second factor must count against the durable, account-scoped
  # AuthThrottle and land in the attempt log, exactly like the password
  # stage and the mail edges - otherwise an attacker holding the password
  # could grind the ~1e6 TOTP space by rotating source IPs past the
  # ephemeral per-IP cache limiter.
  test "wrong TOTP code records a durable throttle failure and a web attempt" do
    start_challenge
    assert_not AuthThrottle.exists?(scope: AuthThrottle::ACCOUNT, key: @user.email_address)

    assert_difference -> { AuthAttempt.where(source: "web").count }, 1 do
      post totp_two_factor_challenge_path, params: { code: "000000" }
    end
    assert_redirected_to new_two_factor_challenge_path
    assert AuthThrottle.exists?(scope: AuthThrottle::ACCOUNT, key: @user.email_address),
      "a wrong second factor must count against the durable account throttle"
  end

  # Once the account's failure budget is spent, the challenge is refused
  # before the code is even checked - a correct code no longer signs in.
  test "a throttled account is refused at the TOTP challenge before the code is checked" do
    start_challenge
    AuthThrottle.max_failures_per_account.times do
      AuthThrottle.record_failure(ip: "203.0.113.9", email: @user.email_address)
    end
    assert AuthThrottle.check(ip: "198.51.100.5", email: @user.email_address),
      "the account should be blocked after exhausting its budget"

    post totp_two_factor_challenge_path, params: { code: ROTP::TOTP.new(@user.otp_secret).now }

    assert_redirected_to new_two_factor_challenge_path
    assert_equal "Too many attempts. Try again later.", flash[:alert]
    assert_nil cookies[:session_id].presence, "a valid code must not sign in while throttled"
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
