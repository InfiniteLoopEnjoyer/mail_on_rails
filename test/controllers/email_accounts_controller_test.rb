require "test_helper"

class EmailAccountsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", name: "Carol", password: "secret123")
  end

  test "requires authentication" do
    sign_out
    get root_url
    assert_redirected_to new_session_url
  end

  test "index lists accounts" do
    get root_url
    assert_response :success
    assert_select ".primary", text: @account.email
  end

  test "creates an account with the default folders" do
    assert_difference "EmailAccount.count", 1 do
      post email_accounts_url, params: { email_account: { email: "dave@example.com", name: "Dave", password: "secret123" } }
    end
    account = EmailAccount.find_by(email: "dave@example.com")
    assert_redirected_to email_account_url(account)
    assert_equal EmailAccount::DEFAULT_MAILBOXES.sort, account.mailboxes.pluck(:name).sort
  end

  test "rejects a duplicate email" do
    assert_no_difference "EmailAccount.count" do
      post email_accounts_url, params: { email_account: { email: @account.email, password: "secret123" } }
    end
    assert_response :unprocessable_entity
  end

  test "updates an account, keeping the password when left blank" do
    patch email_account_url(@account), params: { email_account: { email: "carol@example.org", name: "Carol", password: "" } }
    assert_redirected_to email_account_url(@account)
    @account.reload
    assert_equal "carol@example.org", @account.email
    assert @account.authenticate("secret123")
  end

  test "destroys an account together with its folders" do
    assert_difference "EmailAccount.count", -1 do
      assert_difference "Mailbox.count", -EmailAccount::DEFAULT_MAILBOXES.size do
        delete email_account_url(@account)
      end
    end
    assert_redirected_to root_url
  end
end
