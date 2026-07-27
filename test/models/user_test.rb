require "test_helper"

class UserTest < ActiveSupport::TestCase
  test "downcases and strips email_address" do
    user = User.new(email_address: " DOWNCASED@EXAMPLE.COM ")
    assert_equal("downcased@example.com", user.email_address)
  end

  test "verify_otp accepts a current code once and rejects replays" do
    user = users(:one)
    user.update!(otp_secret: ROTP::Base32.random)
    code = ROTP::TOTP.new(user.otp_secret).now

    assert user.verify_otp(code)
    assert_not user.verify_otp(code), "the same timestep must not verify twice"
  end

  test "verify_otp rejects wrong codes and users without a secret" do
    user = users(:one)
    assert_not user.verify_otp("000000")

    user.update!(otp_secret: ROTP::Base32.random)
    assert_not user.verify_otp("000000")
  end

  test "second_factor_enabled? with otp or a passkey" do
    user = users(:one)
    assert_not user.second_factor_enabled?

    user.update!(otp_secret: ROTP::Base32.random)
    assert user.second_factor_enabled?

    user.update!(otp_secret: nil)
    user.webauthn_credentials.create!(external_id: "abc", public_key: "pk", nickname: "Key")
    assert user.second_factor_enabled?
  end
end
