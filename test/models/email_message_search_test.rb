require "test_helper"

# body_text extraction at delivery time and the tsvector search over it
# (the web search box and the IMAP store's search_text pushdown both
# ride EmailMessage.full_text_search / the search_vector column).
class EmailMessageSearchTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "search@example.com", password: "secret123")
    @inbox = @account.inbox
  end

  test "deliver_raw extracts the plain text part into body_text" do
    message = EmailMessage.deliver_raw(@inbox, <<~RAW)
      From: a@example.com
      Subject: hello
      Content-Type: text/plain

      The kumquat budget is ready.
    RAW

    assert_includes message.body_text, "kumquat budget"
  end

  test "deliver_raw strips tags from html-only messages" do
    raw = "From: a@example.com\r\nSubject: hi\r\nContent-Type: text/html\r\n\r\n" \
          "<p>Hello <b>kumquat</b> world</p>\r\n"
    message = EmailMessage.deliver_raw(@inbox, raw)

    assert_includes message.body_text, "kumquat"
    refute_includes message.body_text, "<b>"
  end

  test "searchable_text survives unparseable messages and invalid bytes" do
    raw = "From: broken\r\n\r\nbody with \xFF invalid bytes\r\n".b
    text = EmailMessage.searchable_text(raw)

    assert text.valid_encoding?, "must be valid UTF-8 for the text column"
    assert_includes text, "invalid bytes"
  end

  test "searchable_text removes NUL bytes and caps the length" do
    raw = "From: a@b\r\n\r\n" + "word\u0000 " + ("x" * (EmailMessage::SEARCHABLE_TEXT_LIMIT + 500))
    text = EmailMessage.searchable_text(raw)

    refute_includes text, "\u0000"
    assert_operator text.length, :<=, EmailMessage::SEARCHABLE_TEXT_LIMIT
  end

  test "full_text_search matches words in subject, addresses, and body" do
    hit = EmailMessage.deliver_raw(@inbox, "From: sender@example.com\r\nSubject: quarterly numbers\r\n\r\nkumquat\r\n")
    EmailMessage.deliver_raw(@inbox, "From: other@example.com\r\nSubject: lunch\r\n\r\nnoon\r\n")

    assert_equal [ hit ], EmailMessage.full_text_search("quarterly").to_a
    assert_equal [ hit ], EmailMessage.full_text_search("KUMQUAT").to_a
    assert_equal [ hit ], EmailMessage.full_text_search("sender@example.com").to_a
    assert_empty EmailMessage.full_text_search("zebra").where(mailbox: @inbox)
  end

  test "full_text_search understands websearch operators" do
    hit = EmailMessage.deliver_raw(@inbox, "Subject: report\r\n\r\nthe kumquat budget\r\n")
    EmailMessage.deliver_raw(@inbox, "Subject: report\r\n\r\nthe zebra budget\r\n")

    assert_equal [ hit ], EmailMessage.full_text_search("budget -zebra").where(mailbox: @inbox).to_a
    assert_equal [ hit ], EmailMessage.full_text_search(%("kumquat budget")).where(mailbox: @inbox).to_a
    # Never raises, whatever the user types.
    assert_nothing_raised { EmailMessage.full_text_search(%[")( OR AND "]).load }
  end

  test "a message too large to index still delivers" do
    raw = "From: a@b\r\nSubject: big\r\n\r\n" + ("lorem ipsum " * 200_000)
    message = EmailMessage.deliver_raw(@inbox, raw)

    assert message.persisted?
    assert_operator message.body_text.length, :<=, EmailMessage::SEARCHABLE_TEXT_LIMIT
  end
end
