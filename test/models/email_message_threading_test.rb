require "test_helper"

# Thread resolution at delivery time: References/In-Reply-To land in
# columns and resolve to an account-wide thread_id (the IMAP THREADID,
# and what the mailbox list groups by).
class EmailMessageThreadingTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "threads@example.com", password: "secret123")
    @inbox = @account.inbox
  end

  def deliver(mailbox, id:, subject: "hi", refs: nil, in_reply_to: nil)
    lines = [ "From: a@example.com", "Subject: #{subject}", "Message-Id: <#{id}>" ]
    lines << "References: #{refs.map { |r| "<#{r}>" }.join(" ")}" if refs
    lines << "In-Reply-To: <#{in_reply_to}>" if in_reply_to
    EmailMessage.deliver_raw(mailbox, lines.join("\r\n") + "\r\n\r\nbody #{id}\r\n")
  end

  test "ancestry headers are extracted into columns" do
    message = deliver(@inbox, id: "r1@x", refs: %w[root@x mid@x], in_reply_to: "mid@x")

    assert_equal "root@x mid@x", message.references_ids
    assert_equal "root@x mid@x", message.references
    assert_equal "mid@x", message.in_reply_to
    assert_match(/\AT[0-9a-f]{24}\z/, message.thread_id)
  end

  test "a reply adopts its ancestor's thread; strangers get their own" do
    root = deliver(@inbox, id: "root@x")
    reply = deliver(@inbox, id: "r1@x", subject: "Re: hi", refs: %w[root@x])
    stranger = deliver(@inbox, id: "other@x", subject: "other")

    assert_equal root.thread_id, reply.thread_id
    refute_equal root.thread_id, stranger.thread_id
  end

  test "a reply referencing only its immediate parent still joins the thread" do
    root = deliver(@inbox, id: "root@x")
    mid = deliver(@inbox, id: "mid@x", refs: %w[root@x])
    leaf = deliver(@inbox, id: "leaf@x", in_reply_to: "mid@x")

    assert_equal root.thread_id, mid.thread_id
    assert_equal root.thread_id, leaf.thread_id
  end

  test "threads converge when the reply arrives before the root" do
    reply = deliver(@inbox, id: "r1@x", refs: %w[root@x])
    root = deliver(@inbox, id: "root@x")

    assert_equal reply.thread_id, root.thread_id
  end

  test "thread ids are account-wide, so the Sent copy joins the conversation" do
    root = deliver(@inbox, id: "root@x")
    sent = deliver(@account.find_mailbox("Sent"), id: "r1@x", refs: %w[root@x])

    assert_equal root.thread_id, sent.thread_id
  end

  test "another account's identical message ids stay separate" do
    other_account = EmailAccount.create!(email: "elsewhere@example.com", password: "secret123")
    mine = deliver(@inbox, id: "root@x")
    reply_elsewhere = deliver(other_account.inbox, id: "r1@x", refs: %w[unrelated@x])

    refute_equal mine.thread_id, reply_elsewhere.thread_id
  end

  test "a message with no ids threads by content" do
    a = EmailMessage.deliver_raw(@inbox, "Subject: a\r\n\r\nsame\r\n")
    b = EmailMessage.deliver_raw(@inbox, "Subject: b\r\n\r\ndifferent\r\n")

    assert a.thread_id.present?
    refute_equal a.thread_id, b.thread_id
  end
end
