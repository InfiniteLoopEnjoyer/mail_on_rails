# Passkey (WebAuthn) relying-party configuration. The browser binds
# credentials to the page origin, so the allowed origin must match exactly
# what users have in the address bar - in production that's the web host the
# deploy overlay sets (MAIL_ON_RAILS_WEB_HOST, see config/deploy.prod.yml).
WebAuthn.configure do |config|
  config.rp_name = "Mail on Rails"
  config.allowed_origins =
    if Rails.env.production?
      [ "https://#{ENV.fetch("MAIL_ON_RAILS_WEB_HOST", "localhost")}" ]
    elsif Rails.env.test?
      [ "http://www.example.com" ]
    else
      [ "http://localhost:3000" ]
    end
end
