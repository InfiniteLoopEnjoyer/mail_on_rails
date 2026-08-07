class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_session_path, alert: "Try again later." }

  def new
  end

  def create
    # Admin-managed permanent bans (BannedIp) and the durable AuthThrottle
    # cover this surface just like the mail edges (Store::Base#authenticate):
    # both refuse before the bcrypt comparison. Rails' cache-backed
    # rate_limit above stays as the cheap first gate. Deliberately the same
    # message for ban and throttle: a blocked scanner learns nothing new.
    if BannedIp.covering(request.remote_ip) ||
       AuthThrottle.check(ip: request.remote_ip, email: params[:email_address])
      AuthAttempt.record(ip: request.remote_ip, username: params[:email_address],
                         source: "web", outcome: "throttled")
      return redirect_to new_session_path, alert: "Try again later."
    end

    if user = User.authenticate_by(params.permit(:email_address, :password))
      if user.second_factor_enabled?
        # No clear_account yet: a password-only success must not refill the
        # budget for an attacker still guessing the second factor. The
        # counter clears in ChallengesController#complete_sign_in.
        stash_pending_second_factor user
        redirect_to new_two_factor_challenge_path
      else
        AuthThrottle.clear_account(user.email_address)
        start_new_session_for user
        redirect_to after_authentication_url
      end
    else
      AuthThrottle.record_failure(ip: request.remote_ip, email: params[:email_address])
      # Recorded so the web login shows up alongside IMAP and SMTP AUTH in
      # the attempt log.
      AuthAttempt.record(ip: request.remote_ip, username: params[:email_address],
                         source: "web", outcome: "bad_credentials")
      redirect_to new_session_path, alert: "Try another email address or password."
    end
  end

  def destroy
    terminate_session
    redirect_to new_session_path, status: :see_other
  end
end
