require "test_helper"

class SecurityHeadersTest < ActionDispatch::IntegrationTest
  test "responses carry an enforcing Content-Security-Policy" do
    get new_session_path

    policy = response.headers["Content-Security-Policy"]
    assert policy.present?, "CSP header missing"
    assert_nil response.headers["Content-Security-Policy-Report-Only"],
      "policy must be enforcing, not report-only"

    assert_match(/script-src 'self' 'nonce-/, policy)
    # unsafe-inline (and no nonce) on style-src: the email srcdoc iframe
    # inherits this policy and its sanitized markup carries inline styles.
    assert_match(/style-src 'self' 'unsafe-inline'/, policy)
    assert_no_match(/style-src[^;]*nonce/, policy)
    # data: for cid-inlined mail images, https: for opt-in remote images.
    assert_match(/img-src 'self' data: https:/, policy)
    assert_match(/object-src 'none'/, policy)
    assert_match(/frame-ancestors 'self'/, policy)
    assert_match(/form-action 'self'/, policy)
    assert_match(%r{connect-src 'self' ws://}, policy)
  end

  test "responses carry Permissions-Policy and Referrer-Policy" do
    get new_session_path

    permissions = response.headers["Permissions-Policy"]
    assert permissions.present?, "Permissions-Policy header missing"
    %w[camera microphone geolocation usb payment].each do |feature|
      assert_match(/#{feature}=\(\)/, permissions)
    end
    # WebAuthn must stay usable: the passkey feature is not denied.
    assert_no_match(/publickey-credentials-get=\(\)/, permissions)

    assert_equal "same-origin", response.headers["Referrer-Policy"]
  end

  # The email iframe is srcdoc-embedded, so its content is governed by the
  # page's own policy - which must therefore tolerate what the sanitizer
  # legitimately lets through (inline styles, data: images).
  test "an HTML email page renders under the policy the srcdoc iframe will inherit" do
    sign_in_as User.take
    account = EmailAccount.create!(email: "csp-check@example.com", password: "secret123")
    raw = "From: sender@remote.test\r\nTo: csp-check@example.com\r\n" \
          "Subject: styled\r\nMessage-ID: <csp1@remote.test>\r\n" \
          "Content-Type: text/html\r\n\r\n" \
          "<html><head><style>p { color: red }</style></head>" \
          "<body><p style=\"font-weight: bold\">hi</p></body></html>\r\n"
    message = EmailMessage.deliver_raw(account.inbox, raw, scan_status: "clean")

    get email_account_mailbox_email_message_url(account, message.mailbox, message)

    assert_response :success
    assert_select "iframe[srcdoc]", 1
    policy = response.headers["Content-Security-Policy"]
    assert_match(/style-src 'self' 'unsafe-inline'/, policy)
    assert_match(/img-src 'self' data: https:/, policy)
  end

  test "layout scripts carry the CSP nonce" do
    get new_session_path

    nonce = response.headers["Content-Security-Policy"][/'nonce-([^']+)'/, 1]
    assert nonce.present?

    # Both the theme pre-paint script and the importmap-generated inline
    # scripts must be nonced or the browser refuses to run them.
    assert_select "script[nonce]" do |scripts|
      assert scripts.any? { |s| s.text.include?("prefers-color-scheme") },
        "theme pre-paint script must carry the nonce"
    end
    assert_select "script:not([src]):not([nonce]):not([type=?])", "application/json", count: 0
  end
end
