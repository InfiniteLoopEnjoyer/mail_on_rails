# The signed-in user's two-factor settings: registered passkeys and the
# authenticator-app fallback. Enrollment itself happens in the
# TwoFactor::Passkeys / TwoFactor::Totp controllers.
class SecurityController < ApplicationController
  def show
    @user = Current.user
    @passkeys = @user.webauthn_credentials.order(:created_at)
  end
end
