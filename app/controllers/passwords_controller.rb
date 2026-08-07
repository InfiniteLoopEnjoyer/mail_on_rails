class PasswordsController < ApplicationController
  allow_unauthenticated_access
  before_action :set_user_by_token, only: %i[ edit update ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_password_path, alert: "Try again later." }
  # update is reached by reset token; brake token guessing the same way.
  # Prepended so it counts the attempt before set_user_by_token rejects a
  # bad token - otherwise guesses would never reach the limiter.
  rate_limit to: 10, within: 3.minutes, only: :update, name: "update", prepend: true,
             with: -> { redirect_to new_password_path, alert: "Try again later." }

  def new
  end

  def create
    if user = User.find_by(email_address: params[:email_address])
      PasswordsMailer.reset(user).deliver_later
    end

    redirect_to new_session_path, notice: "Password reset instructions sent (if user with that email address exists)."
  end

  def edit
  end

  # Rotating the digest also kills the reset token (it embeds the password
  # salt), so the generated password really is shown exactly once: the HTML
  # fallback must render, not redirect back to the now-dead token URL.
  def update
    @generated_password = @user.regenerate_password!
    @user.sessions.destroy_all
    respond_to do |format|
      format.turbo_stream do
        render turbo_stream: turbo_stream.replace(
          "password-generator",
          partial: "shared/password_generator",
          locals: { url: password_path(params[:token]), method: :put, password: @generated_password, signin_link: true }
        )
      end
      format.html { render :edit }
    end
  end

  private
    def set_user_by_token
      @user = User.find_by_password_reset_token!(params[:token])
    rescue ActiveSupport::MessageVerifier::InvalidSignature
      redirect_to new_password_path, alert: "Password reset link is invalid or has expired."
    end
end
