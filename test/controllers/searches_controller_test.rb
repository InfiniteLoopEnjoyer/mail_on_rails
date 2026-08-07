require "test_helper"

class SearchesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "finder@example.com", password: "secret123")
    @inbox = @account.inbox
  end

  test "an empty query renders the search form without results" do
    get email_account_search_url(@account)

    assert_response :success
    assert_select "input[type=search]"
    assert_select "li a span.primary", 0
  end

  test "matching messages are listed with their folder" do
    EmailMessage.deliver_raw(@inbox, "From: a@example.com\r\nSubject: kumquat news\r\n\r\nhello\r\n")
    EmailMessage.deliver_raw(@account.find_mailbox("Sent"),
                             "From: finder@example.com\r\nSubject: re: kumquat\r\n\r\nreply\r\n")
    EmailMessage.deliver_raw(@inbox, "From: a@example.com\r\nSubject: lunch\r\n\r\nnoon\r\n")

    get email_account_search_url(@account, q: "kumquat")

    assert_response :success
    assert_select "li a span.primary", 2
    # Search spans folders, so each hit names where it lives.
    assert_select "li a span", text: "Sent"
    assert_select "li a span", text: "INBOX"
  end

  test "no matches says so" do
    get email_account_search_url(@account, q: "zebra")

    assert_response :success
    assert_select "p", text: /No messages match/
  end

  test "results paginate" do
    (SearchesController::MESSAGES_PER_PAGE + 2).times do |i|
      EmailMessage.deliver_raw(@inbox, "Subject: kumquat #{i}\r\n\r\nbody\r\n")
    end

    get email_account_search_url(@account, q: "kumquat")
    assert_select "li a span.primary", SearchesController::MESSAGES_PER_PAGE
    assert_select "nav[aria-label='Pagination']"

    get email_account_search_url(@account, q: "kumquat", page: 2)
    assert_select "li a span.primary", 2
  end
end
