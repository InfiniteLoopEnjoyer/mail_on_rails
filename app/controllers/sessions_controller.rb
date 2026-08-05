class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_session_path, alert: "Try again later." }

  def new
  end

  def create
    # Admin-managed permanent bans (BannedIp) cover this surface too - the
    # mail edges drop banned connections before they speak, the web login
    # refuses before touching credentials. Deliberately the same message
    # as the rate limit: a banned scanner learns nothing new.
    if BannedIp.covering(request.remote_ip)
      AuthAttempt.record(ip: request.remote_ip, username: params[:email_address],
                         source: "web", outcome: "throttled")
      return redirect_to new_session_path, alert: "Try again later."
    end

    if user = User.authenticate_by(params.permit(:email_address, :password))
      if user.second_factor_enabled?
        stash_pending_second_factor user
        redirect_to new_two_factor_challenge_path
      else
        start_new_session_for user
        redirect_to after_authentication_url
      end
    else
      # Recorded so the web login shows up alongside IMAP and SMTP AUTH in
      # the attempt log. Enforcement here stays Rails' own rate_limit above
      # (per-IP, cache-backed); this is the audit trail, not a second gate.
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
