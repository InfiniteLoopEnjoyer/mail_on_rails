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
    assert_select "turbo-cable-stream-source", 1
  end

  test "index sorts regular accounts by domain then email and splits dmarc and tls-rpt accounts into their own lists" do
    EmailAccount.create!(email: "zed@aardvark.test", name: "Zed", password: "secret123")
    EmailAccount.create!(email: "amy@zebra.test", name: "Amy", password: "secret123")
    domain = Domain.create!(name: "example.com")

    get root_url
    assert_response :success
    assert_select "ul", 3
    emails = css_select("ul:first-of-type .primary").map(&:text)
    assert_equal [ "zed@aardvark.test", "carol@example.com", "amy@zebra.test" ], emails
    assert_equal [ domain.dmarc_address ], css_select("ul:nth-of-type(2) .primary").map(&:text)
    assert_equal [ domain.tls_rpt_address ], css_select("ul:last-of-type .primary").map(&:text)
  end

  test "account page subscribes to live updates" do
    get email_account_url(@account)
    assert_response :success
    assert_select "turbo-cable-stream-source", 1
  end

  test "index shows an unread count when an account has unseen messages" do
    raw = "From: a@example.com\r\nTo: #{@account.email}\r\nSubject: hi\r\n\r\nbody\r\n"
    EmailMessage.deliver_raw(@account.inbox, raw)
    EmailMessage.deliver_raw(@account.inbox, raw, flags: [ "\\Seen" ])

    get root_url
    assert_response :success
    assert_select "span", text: "1 unread"
  end

  test "account page shows unseen/total per mailbox, or just the total when all seen" do
    raw = "From: a@example.com\r\nTo: #{@account.email}\r\nSubject: hi\r\n\r\nbody\r\n"
    EmailMessage.deliver_raw(@account.inbox, raw)
    EmailMessage.deliver_raw(@account.inbox, raw, flags: [ "\\Seen" ])
    sent = @account.mailboxes.find_by!(name: "Sent")
    EmailMessage.deliver_raw(sent, raw, flags: [ "\\Seen" ])

    get email_account_url(@account)

    assert_response :success
    assert_select "span", text: "1 new / 2"
    assert_select "li" do |items|
      sent_row = items.find { |li| li.text.include?("Sent") }
      assert_includes sent_row.text, "1"
      assert_not_includes sent_row.text, "new /"
    end
  end

  test "creates an account with the default folders and a generated password shown once" do
    assert_difference "EmailAccount.count", 1 do
      post email_accounts_url, params: { email_account: { email: "dave@example.com", name: "Dave" } }
    end
    account = EmailAccount.find_by(email: "dave@example.com")
    assert_redirected_to email_account_url(account)
    assert_equal EmailAccount::DEFAULT_MAILBOXES.sort, account.mailboxes.pluck(:name).sort

    follow_redirect!
    plaintext = extract_generated_password
    assert account.authenticate(plaintext)

    get email_account_url(account)
    assert_not_includes response.body, plaintext
  end

  test "rejects a duplicate email" do
    assert_no_difference "EmailAccount.count" do
      post email_accounts_url, params: { email_account: { email: @account.email } }
    end
    assert_response :unprocessable_entity
  end

  test "update ignores password params" do
    patch email_account_url(@account), params: { email_account: { email: "carol@example.org", name: "Carol", password: "sneaky" } }
    assert_redirected_to email_account_url(@account)
    @account.reload
    assert_equal "carol@example.org", @account.email
    assert @account.authenticate("secret123")
    assert_not @account.authenticate("sneaky")
  end

  test "generate_password rotates the digest and shows the password once" do
    post generate_password_email_account_url(@account), headers: { "Accept" => "text/vnd.turbo-stream.html" }
    assert_response :success
    assert_select "turbo-stream[action=replace][target=password-generator]"

    plaintext = extract_generated_password
    @account.reload
    assert @account.authenticate(plaintext)
    assert_not @account.authenticate("secret123")

    get edit_email_account_url(@account)
    assert_not_includes response.body, plaintext
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
