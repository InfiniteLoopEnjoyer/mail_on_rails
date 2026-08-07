# Enforcing CSP for the admin UI. Email HTML renders inside an iframe via
# srcdoc (email_messages/show), and srcdoc documents inherit this policy, so
# it must allow everything sanitizer output can legitimately contain - see
# the style-src and img-src notes below.
Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self

    if Rails.env.development?
      # web-console injects non-nonced inline scripts on error pages, and
      # unsafe_inline is ignored whenever a nonce is present - so dev also
      # skips the nonce directive (below).
      policy.script_src :self, :unsafe_inline
    else
      policy.script_src :self # + per-request nonce via nonce_directives
    end

    # unsafe_inline is load-bearing: Turbo's progress bar, a couple of
    # style= attributes in views, and - because the srcdoc iframe inherits
    # this policy - the sanitized <style> block and style attributes of
    # HTML mail. NEVER add a nonce to style-src: a nonce in the directive
    # makes browsers ignore unsafe-inline and silently break mail styling.
    policy.style_src :self, :unsafe_inline

    # data: carries cid-inlined mail images, the blocked-image placeholder
    # pixel and Lexxy's icons; https: is the opt-in remote-image path
    # (?images=1). http: images are mixed content on an HTTPS page and were
    # already blocked by the browser.
    policy.img_src :self, :data, :https

    policy.font_src :self
    policy.object_src :none
    policy.frame_src :self       # the message srcdoc iframe
    policy.frame_ancestors :self # matches the X-Frame-Options SAMEORIGIN default
    policy.base_uri :self
    policy.form_action :self

    # Action Cable: 'self' does not reliably match wss:// across engines,
    # so name the websocket origin per request. The proc is instance_exec'd
    # against the controller on renders but against the bare request on
    # middleware-emitted responses - resolve either way.
    policy.connect_src :self, -> {
      req = is_a?(ActionDispatch::Request) ? self : request
      "#{req.ssl? ? "wss" : "ws"}://#{req.host_with_port}"
    }
  end

  # Session-bound nonce (not per-request randomness): Turbo's page cache
  # restores earlier HTML, whose nonces must still match the current header.
  # A brand-new visitor has no committed session id yet - fall back to a
  # random value (computed once per request, so header and tags agree).
  config.content_security_policy_nonce_generator =
    ->(request) { request.session.id.to_s.presence || SecureRandom.base64(16) }
  config.content_security_policy_nonce_directives = %w[script-src] unless Rails.env.development?
end
