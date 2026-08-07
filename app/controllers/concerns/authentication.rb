module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :require_authentication
    helper_method :authenticated?
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :require_authentication, **options
    end
  end

  private
    def authenticated?
      resume_session
    end

    def require_authentication
      resume_session || request_authentication
    end

    def resume_session
      Current.session ||= find_session_by_cookie
    end

    def find_session_by_cookie
      Session.find_by(id: cookies.signed[:session_id]) if cookies.signed[:session_id]
    end

    def request_authentication
      # Store only the path+query (host-independent), and only for GETs - a
      # non-GET couldn't be replayed by redirect anyway.
      session[:return_to_after_authenticating] = request.fullpath if request.get?
      redirect_to new_session_path
    end

    def after_authentication_url
      # url_from rejects anything not same-origin: absolute URLs to other
      # hosts and protocol-relative "//evil.example/..." (which fullpath can
      # still produce for a crafted request line).
      url_from(session.delete(:return_to_after_authenticating)) || root_url
    end

    # Password accepted but a second factor is required: park the user id in
    # the (encrypted, short-lived) cookie session until the challenge is
    # passed. No Session row exists yet, so nothing else is accessible.
    SECOND_FACTOR_GRACE = 5.minutes

    def stash_pending_second_factor(user)
      session[:two_factor_user_id] = user.id
      session[:two_factor_deadline] = SECOND_FACTOR_GRACE.from_now.to_i
    end

    def pending_second_factor_user
      return nil if session[:two_factor_deadline].to_i < Time.current.to_i
      User.find_by(id: session[:two_factor_user_id])
    end

    def clear_pending_second_factor
      session.delete(:two_factor_user_id)
      session.delete(:two_factor_deadline)
    end

    def start_new_session_for(user)
      user.sessions.create!(user_agent: request.user_agent, ip_address: request.remote_ip).tap do |session|
        Current.session = session
        cookies.signed.permanent[:session_id] = { value: session.id, httponly: true, same_site: :lax }
      end
    end

    def terminate_session
      Current.session.destroy
      cookies.delete(:session_id)
    end
end
