require "test_helper"

# Real-browser tests, for behaviour that only exists once JavaScript runs -
# the composer's autosave in particular, which no request-level test can
# reach. Headless Chrome; there is no display on the deploy host or in CI.
class ApplicationSystemTestCase < ActionDispatch::SystemTestCase
  driven_by :selenium, using: :headless_chrome, screen_size: [ 1400, 1400 ] do |options|
    # Chrome refuses to start as root without --no-sandbox, which is how it
    # runs in the container.
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
  end

  # Signs in through the form; the cookie-jar shortcut the integration tests
  # use isn't available to a real browser.
  def sign_in_as(user, password: "password")
    visit new_session_url
    fill_in "Enter your email address", with: user.email_address
    fill_in "Enter your password", with: password
    click_on "Sign in"
    assert_no_current_path new_session_path, wait: 5
  end
end
