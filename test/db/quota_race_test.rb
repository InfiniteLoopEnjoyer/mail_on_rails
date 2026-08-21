# frozen_string_literal: true

require_relative "test_helper"

# The storage-quota gate must be a real bound, not a check-then-write race:
# concurrent deliveries to an account with room for one more message must
# not both succeed. The db suite runs on file-backed SQLite (or the CI
# matrix's PG/MySQL), so the row lock is exercised for real.
class QuotaRaceTest < DbSuite::TestCase
  def raw(size)
    body = "x" * size
    "Message-ID: <#{SecureRandom.hex(8)}@local.test>\r\nSubject: hi\r\n\r\n#{body}\r\n"
  end

  def setup
    super
    @account = MailOnRails::EmailAccount.create!(email: "user@example.test", password: "pw-123456")
    @inbox = @account.inbox
  end

  test "a delivery over quota is refused and does not change used_bytes" do
    message = raw(1000)
    @account.update!(quota_bytes: message.bytesize + 10)

    MailOnRails::EmailMessage.deliver_raw(@inbox, message)
    before = @account.reload.used_bytes

    assert_raises(MailOnRails::EmailMessage::OverQuota) do
      MailOnRails::EmailMessage.deliver_raw(@inbox, raw(1000))
    end
    assert_equal before, @account.reload.used_bytes, "a refused delivery must not move the counter"
  end

  test "concurrent deliveries cannot both slip past a one-message quota" do
    message_size = raw(2000).bytesize
    # Room for exactly one message.
    @account.update!(quota_bytes: message_size + 100)

    results = []
    mutex = Mutex.new
    threads = 4.times.map do
      Thread.new do
        outcome =
          begin
            MailOnRails::EmailMessage.deliver_raw(@inbox, raw(2000))
            :stored
          rescue MailOnRails::EmailMessage::OverQuota
            :refused
          rescue ActiveRecord::RecordNotUnique, ActiveRecord::Deadlocked
            :retry_conflict
          ensure
            ActiveRecord::Base.connection_pool.release_connection
          end
        mutex.synchronize { results << outcome }
      end
    end
    threads.each(&:join)

    assert_equal 1, results.count(:stored), "exactly one delivery may win the last slot (got #{results.inspect})"
    assert_equal 1, @inbox.email_messages.count
    assert_operator @account.reload.used_bytes, :<=, @account.quota_bytes
  end
end
