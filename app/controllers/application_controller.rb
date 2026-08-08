class ApplicationController < ActionController::Base
  include Authentication
  include Auditing
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  # Changes to the importmap will invalidate the etag for HTML responses
  stale_when_importmap_changes

  # Deployment-wide second-factor mandate (MAIL_ON_RAILS_REQUIRE_2FA=1).
  # Every web session is currently full admin, so in a multi-person
  # deployment one password-only account is the whole system's weakest
  # link; with this set, a signed-in user without a second factor is
  # parked on enrollment until one exists. Runs after
  # require_authentication, so Current.user is only present where a
  # session was actually resumed - token/unauthenticated endpoints
  # (metrics, health, MTA-STS, login itself) are naturally unaffected.
  before_action :require_second_factor_enrollment

  private

  def require_second_factor_enrollment
    return unless ActiveModel::Type::Boolean.new.cast(ENV["MAIL_ON_RAILS_REQUIRE_2FA"])
    return unless Current.user
    return if Current.user.second_factor_enabled?
    return if second_factor_enrollment_surface?

    redirect_to new_two_factor_totp_path,
                alert: "This server requires two-factor authentication. Enroll an authenticator app, or add a passkey from your profile, to continue."
  end

  # The pages an un-enrolled user still needs: both enrollment flows
  # (TOTP QR page, passkey registration - the latter lives on the user's
  # own profile), and signing out. Everything else redirects.
  def second_factor_enrollment_surface?
    case controller_path
    when "two_factor/totp", "two_factor/passkeys", "sessions" then true
    when "users"
      %w[edit update].include?(action_name) && params[:id].to_s == Current.user.id.to_s
    else
      false
    end
  end
end
