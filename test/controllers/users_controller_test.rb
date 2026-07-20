require "test_helper"

class UsersControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:one)
    sign_in_as @user
  end

  test "requires authentication" do
    sign_out
    get users_url
    assert_redirected_to new_session_url
  end

  test "index lists users" do
    get users_url
    assert_response :success
    assert_select ".primary", text: @user.email_address
  end

  test "creates a user" do
    assert_difference "User.count", 1 do
      post users_url, params: { user: { email_address: "new@example.com", password: "secret123" } }
    end
    assert_redirected_to users_url
  end

  test "rejects a duplicate email address" do
    assert_no_difference "User.count" do
      post users_url, params: { user: { email_address: @user.email_address, password: "secret123" } }
    end
    assert_response :unprocessable_entity
  end

  test "updates a user, keeping the password when left blank" do
    other = users(:two)
    patch user_url(other), params: { user: { email_address: "renamed@example.com", password: "" } }
    assert_redirected_to users_url
    other.reload
    assert_equal "renamed@example.com", other.email_address
    assert other.authenticate("password")
  end

  test "destroys a user" do
    assert_difference "User.count", -1 do
      delete user_url(users(:two))
    end
    assert_redirected_to users_url
  end

  test "refuses to destroy the signed-in user" do
    assert_no_difference "User.count" do
      delete user_url(@user)
    end
    assert_redirected_to users_url
    assert flash[:alert].present?
  end
end
