# Passkey enrollment for the signed-in user (see the user edit page).
# options issues the creation challenge; create verifies the attestation the
# browser posts back (webauthn_controller.js) and stores the public key.
class TwoFactor::PasskeysController < ApplicationController
  def options
    user = Current.user
    options = WebAuthn::Credential.options_for_create(
      user: { id: user.webauthn_handle, name: user.email_address },
      exclude: user.webauthn_credentials.pluck(:external_id)
    )
    session[:webauthn_challenge] = options.challenge
    render json: options
  end

  def create
    credential = WebAuthn::Credential.from_create(params.require(:credential).to_unsafe_h)
    credential.verify(session.delete(:webauthn_challenge).to_s)
    Current.user.webauthn_credentials.create!(
      external_id: credential.id,
      public_key: credential.public_key,
      sign_count: credential.sign_count,
      nickname: params[:nickname].presence || "Passkey"
    )
    flash[:notice] = "Passkey registered."
    render json: { location: edit_user_url(Current.user) }
  rescue WebAuthn::Error, ActiveRecord::RecordInvalid, ActionController::ParameterMissing
    render json: { error: "Passkey registration failed." }, status: :unprocessable_entity
  end

  def destroy
    Current.user.webauthn_credentials.find(params[:id]).destroy!
    redirect_to edit_user_path(Current.user), notice: "Passkey removed."
  end
end
