require "test_helper"

class EmailAliasesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
  end

  test "adds an alias" do
    assert_difference "@account.email_aliases.count", 1 do
      post email_account_email_aliases_url(@account), params: { email_alias: { email: "Sales@Example.com" } }
    end
    assert_redirected_to email_account_url(@account)
    assert_equal "sales@example.com", @account.email_aliases.sole.email
  end

  test "rejects an alias that is already an account address" do
    assert_no_difference "EmailAlias.count" do
      post email_account_email_aliases_url(@account), params: { email_alias: { email: @account.email } }
    end
    assert_redirected_to email_account_url(@account)
    assert flash[:alert].present?
  end

  test "removes an alias" do
    email_alias = @account.email_aliases.create!(email: "sales@example.com")
    assert_difference "EmailAlias.count", -1 do
      delete email_account_email_alias_url(@account, email_alias)
    end
    assert_redirected_to email_account_url(@account)
  end

  test "cannot remove another account's alias" do
    other = EmailAccount.create!(email: "dave@example.com", password: "secret123")
    email_alias = other.email_aliases.create!(email: "sales@example.com")

    assert_no_difference "EmailAlias.count" do
      delete email_account_email_alias_url(@account, email_alias)
    end
    assert_response :not_found
  end
end
