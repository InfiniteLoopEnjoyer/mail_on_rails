# Authenticator-app (TOTP) enrollment, the fallback second factor. new shows
# a QR code for a candidate secret held only in the session; create saves it
# once the user proves their app has it by entering a valid code.
class TwoFactor::TotpController < ApplicationController
  # Same budget as the login-time 2FA challenge: create verifies codes, so
  # it must not be a free oracle for guessing the pending secret's output.
  rate_limit to: 10, within: 3.minutes, only: %i[create destroy],
             with: -> { redirect_to new_two_factor_totp_path, alert: "Try again later." }

  def new
    session[:pending_totp_secret] ||= ROTP::Base32.random
    @secret = session[:pending_totp_secret]
    uri = Current.user.otp_provisioning_uri(@secret)
    @qr_svg = RQRCode::QRCode.new(uri).as_svg(module_size: 4, viewbox: true, use_path: true)
  end

  def create
    secret = session[:pending_totp_secret]
    timestep = secret && ROTP::TOTP.new(secret).verify(
      params[:code].to_s.delete(" "),
      drift_behind: User::OTP_DRIFT, drift_ahead: User::OTP_DRIFT
    )
    if timestep
      Current.user.update!(otp_secret: secret, otp_last_used_at: timestep)
      session.delete(:pending_totp_secret)
      redirect_to edit_user_path(Current.user), notice: "Authenticator app enabled."
    else
      redirect_to new_two_factor_totp_path, alert: "That code didn't match. Scan the QR code and try again."
    end
  end

  def destroy
    Current.user.update!(otp_secret: nil, otp_last_used_at: nil)
    redirect_to edit_user_path(Current.user), notice: "Authenticator app disabled."
  end
end
