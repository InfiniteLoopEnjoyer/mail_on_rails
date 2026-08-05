require "test_helper"

class ThemesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
  end

  test "requires authentication" do
    sign_out
    patch theme_url, params: { appearance: "dark" }
    assert_redirected_to new_session_url
  end

  test "saves appearance and accent, each on its own" do
    patch theme_url, params: { appearance: "dark" }
    assert_response :no_content
    assert_equal "dark", users(:one).reload.appearance

    patch theme_url, params: { accent: "violet" }
    assert_response :no_content
    users(:one).reload
    assert_equal "violet", users(:one).accent
    assert_equal "dark", users(:one).appearance, "accent update must not touch appearance"
  end

  test "rejects values outside the catalogue" do
    patch theme_url, params: { appearance: "blinding" }
    assert_response :unprocessable_entity
    assert_equal "system", users(:one).reload.appearance

    patch theme_url, params: { accent: "beige" }
    assert_response :unprocessable_entity
    assert_equal "crimson", users(:one).reload.accent
  end

  test "layout paints the saved theme onto html" do
    users(:one).update!(appearance: "dark", accent: "sky")
    get root_url
    assert_select "html.dark[data-appearance=dark][data-accent=sky]"

    users(:one).update!(appearance: "light", accent: "crimson")
    get root_url
    assert_select "html[data-appearance=light][data-accent=crimson]"
    assert_select "html.dark", false

    sign_out
    get new_session_url
    assert_select "html[data-appearance=system][data-accent=crimson]"
    assert_select "html.dark", false
  end
end
