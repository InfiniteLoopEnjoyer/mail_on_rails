require "test_helper"

class LayoutTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
  end

  test "layout renders drawer chrome when signed in" do
    get root_url
    assert_response :success

    assert_select "aside[aria-label='Main navigation']" do
      assert_select "nav a", text: "Domains"
      assert_select "nav a", text: "Mailboxes"
      assert_select "nav a", text: "Users"
    end
    assert_select "header" do
      assert_select "a", text: "Mail on Rails"
      assert_select "button", text: "Sign out"
      assert_select "button[aria-label='Toggle navigation']"
    end
    assert_select "[data-controller='drawer']"
    assert_select "[data-drawer-target='backdrop']"

    # link order: Domains, then child Mailboxes, then Users
    links = css_select("aside nav a").map(&:text)
    assert_equal %w[Domains Mailboxes Users], links
  end

  test "mailboxes child link is active on root, domains link active on domains" do
    get root_url
    assert_select "aside nav a.text-accent", text: "Mailboxes"

    get domains_url
    assert_select "aside nav a.text-accent", text: "Domains"
  end

  test "signed out pages have no drawer" do
    delete session_url
    get new_session_url
    assert_response :success
    assert_select "aside", count: 0
    assert_select "header", count: 0
    assert_select "title", text: "Mail on Rails - Sign in"
  end
end
