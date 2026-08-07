# The second step of sign-in for users with a second factor enrolled.
# SessionsController#create parked the user id in the cookie session
# (stash_pending_second_factor); no Session row exists until a factor here
# succeeds. Passkeys verify over JSON (see webauthn_controller.js), the TOTP
# fallback is a plain form post.
class TwoFactor::ChallengesController < ApplicationController
  allow_unauthenticated_access
  rate_limit to: 10, within: 3.minutes, only: :totp,
    with: -> { redirect_to new_two_factor_challenge_path, alert: "Try again later." }
  # The passkey endpoints answer JSON (webauthn_controller.js shows
  # result.error); a separate name so the counters don't merge with totp's.
  rate_limit to: 10, within: 3.minutes, only: %i[ webauthn_options webauthn ], name: "webauthn",
    with: -> { render json: { error: "Try again later." }, status: :too_many_requests }
  before_action :set_user

  def new
  end

  def webauthn_options
    options = WebAuthn::Credential.options_for_get(
      allow: @user.webauthn_credentials.pluck(:external_id),
      user_verification: "preferred"
    )
    session[:webauthn_challenge] = options.challenge
    render json: options
  end

  def webauthn
    credential = WebAuthn::Credential.from_get(params.require(:credential).to_unsafe_h)
    stored = @user.webauthn_credentials.find_by!(external_id: credential.id)
    credential.verify(session.delete(:webauthn_challenge).to_s,
      public_key: stored.public_key, sign_count: stored.sign_count)
    stored.update!(sign_count: credential.sign_count)
    render json: { location: complete_sign_in }
  rescue WebAuthn::Error, ActiveRecord::RecordNotFound, ActionController::ParameterMissing
    render json: { error: "Passkey verification failed." }, status: :unprocessable_entity
  end

  def totp
    if @user.verify_otp(params[:code])
      redirect_to complete_sign_in
    else
      redirect_to new_two_factor_challenge_path, alert: "That code didn't work. Try again."
    end
  end

  private
    def set_user
      @user = pending_second_factor_user
      return if @user

      clear_pending_second_factor
      if request.format.json?
        render json: { error: "Sign-in expired." }, status: :unauthorized
      else
        redirect_to new_session_path, alert: "Please sign in again."
      end
    end

    # Returns the post-login URL so both the JSON (passkey) and redirect
    # (TOTP) paths can send the browser to the same place.
    def complete_sign_in
      clear_pending_second_factor
      # Full sign-in is where the AuthThrottle budget refills for 2FA users;
      # SessionsController#create deliberately skipped it at password stage.
      AuthThrottle.clear_account(@user.email_address)
      start_new_session_for @user
      after_authentication_url
    end
end
