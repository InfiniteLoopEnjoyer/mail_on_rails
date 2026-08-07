require "test_helper"

# Storage quotas: used_bytes tracks the sum of stored message sizes
# incrementally, deliver_raw is the central enforcement gate for every
# write path, and same-account moves stay exempt so a full account can
# still file mail into Trash.
class EmailAccountQuotaTest < ActiveSupport::TestCase
  RAW = "From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n"

  setup do
    @account = EmailAccount.create!(email: "quota@example.com", password: "secret123")
    @inbox = @account.inbox
  end

  test "used_bytes rises on delivery and falls on destroy" do
    assert_equal 0, @account.used_bytes

    message = EmailMessage.deliver_raw(@inbox, RAW)
    assert_equal message.size, @account.reload.used_bytes

    message.destroy!
    assert_equal 0, @account.reload.used_bytes
  end

  test "used_bytes counts the CRLF-normalized size of bare-LF input" do
    bare = RAW.gsub("\r\n", "\n")
    EmailMessage.deliver_raw(@inbox, bare)
    assert_equal RAW.bytesize, @account.reload.used_bytes
  end

  test "deliver_raw raises OverQuota once the account is full" do
    @account.update!(quota_bytes: RAW.bytesize)
    EmailMessage.deliver_raw(@inbox, RAW)

    error = assert_raises(EmailMessage::OverQuota) { EmailMessage.deliver_raw(@inbox.reload, RAW) }
    assert_match(/over its storage quota/, error.message)
    assert_equal RAW.bytesize, @account.reload.used_bytes, "the refused message must not be counted"
  end

  test "a move within the account succeeds even when full" do
    @account.update!(quota_bytes: RAW.bytesize)
    message = EmailMessage.deliver_raw(@inbox, RAW)

    moved = message.move_to!(@account.find_mailbox("Trash"))
    assert_equal "Trash", moved.mailbox.name
    assert_equal RAW.bytesize, @account.reload.used_bytes, "a move is net-zero"
  end

  test "an account without a quota never refuses" do
    assert_not @account.quota_exceeded_by?(10**12)
    assert_nil @account.used_percent
  end

  test "quota_megabytes round-trips whole megabytes and blank means unlimited" do
    @account.quota_megabytes = "100"
    assert_equal 100 * 1_048_576, @account.quota_bytes
    assert_equal 100, @account.quota_megabytes

    @account.quota_megabytes = ""
    assert_nil @account.quota_bytes
  end

  test "used_percent reports rounded usage against the limit" do
    @account.update!(quota_bytes: 1000, used_bytes: 247)
    assert_equal 25, @account.used_percent
  end
end
