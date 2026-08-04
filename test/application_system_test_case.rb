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

  # Waits for the composer's next autosave to land, then reloads whatever
  # the caller passes.
  #
  # The status text is not a usable signal on its own: after the first save
  # it already reads "Saved to Drafts", so asserting on it passes instantly
  # and reads stale data. Every save mints a new revision id, so watching
  # that turn over is the signal that this particular save completed.
  # Types into a composer field and confirms the text actually landed.
  #
  # Selenium will start typing as soon as the element is present, which can
  # be before the page has finished initialising; Chrome drops keystrokes
  # sent in that window, and the field ends up holding half a sentence. A
  # test that then asserts on the saved draft passes or fails on a truncated
  # string it never checked, so the fill is verified and retried here rather
  # than trusted.
  def compose(field, text)
    locator = "composed_email[#{field}]"
    # Keystrokes sent while the document is still loading go nowhere.
    page.document.synchronize(5) do
      raise Capybara::ExpectationNotMet unless page.evaluate_script("document.readyState") == "complete"
    end

    3.times do
      fill_in locator, with: text
      return if page.has_field?(locator, with: text, wait: 2)
    end

    # A starved CI runner can drop the synthetic typing wholesale - the
    # field still holds its previous value after all three attempts. Set
    # the value directly and fire the input event a keystroke would have:
    # what these tests verify is the Stimulus wiring reacting to input,
    # not Chrome's keyboard emulation.
    page.execute_script(<<~JS, find_field(locator, visible: :all), text)
      const [field, value] = arguments;
      field.value = value;
      field.dispatchEvent(new Event("input", { bubbles: true }));
    JS
    assert_field locator, with: text
  end

  # Polls the field's live value rather than matching on [value=...]: a CSS
  # attribute selector reads the HTML attribute, which never changes once
  # rendered, while the autosave assigns the DOM property.
  def wait_for_autosave(timeout: 15)
    field = "input[name='composed_email[draft_message_id]']"
    before = page.find(field, visible: :all).value
    yield if block_given?

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      current = page.find(field, visible: :all).value
      return current if current.present? && current != before
      flunk "autosave did not complete within #{timeout}s" if
        Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.2
    end
  end

  # Accepts the data-turbo-confirm dialog raised by clicking `locator`.
  #
  # Turbo's confirm interceptor exists only once its module has executed; a
  # click that lands before then submits the form natively - the action goes
  # through unconfirmed and accept_confirm times out waiting for a dialog
  # that never opened. Seen on CI's slower runners, so wait for Turbo first.
  def accept_turbo_confirm(locator)
    page.document.synchronize(5) do
      raise Capybara::ExpectationNotMet unless page.evaluate_script("!!window.Turbo")
    end
    accept_confirm { click_on locator }
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
