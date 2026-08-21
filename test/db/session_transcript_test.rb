# frozen_string_literal: true

require_relative "test_helper"

# SessionTranscript persistence through ClosedConnection.record: a captured
# transcript in the close payload lands as a linked row, rolled-up scanner
# noise never stores one, and retention prunes on its own (short) clock.
class SessionTranscriptTest < DbSuite::TestCase
  def teardown
    ENV.delete("MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP")
    ENV.delete("MAIL_ON_RAILS_TRANSCRIPT_RETENTION_DAYS")
  end

  def close_info(**extra)
    { protocol: "smtp", ip: "203.0.113.9", port: 25, role: :mx,
      connected_at: 2.minutes.ago, closed_at: Time.current,
      duration_seconds: 120.0, helo: "client.test" }.merge(extra)
  end

  test "a captured transcript lands as a row linked from the history row" do
    MailOnRails::ClosedConnection.record(
      close_info(transcript: "<= EHLO client.test\n=> 250 OK", close_reason: "timeout")
    )
    connection = MailOnRails::ClosedConnection.where(rollup: false).sole
    transcript = MailOnRails::SessionTranscript.find(connection.transcript_id)
    assert_equal "timeout", transcript.close_reason
    assert_equal "smtp", transcript.protocol
    assert_equal "203.0.113.9", transcript.ip
    assert_equal "client.test", transcript.helo
    assert_includes transcript.transcript, "EHLO client.test"
  end

  test "a close without a capture stores no transcript" do
    MailOnRails::ClosedConnection.record(close_info)
    assert_nil MailOnRails::ClosedConnection.where(rollup: false).sole.transcript_id
    assert_equal 0, MailOnRails::SessionTranscript.count
  end

  test "rolled-up scanner noise past the per-IP cap stores no transcript" do
    ENV["MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP"] = "2"
    3.times do
      MailOnRails::ClosedConnection.record(
        close_info(transcript: "<= BOGUS\n=> 502", close_reason: "protocol_errors")
      )
    end
    assert_equal 2, MailOnRails::SessionTranscript.count
    assert_equal 1, MailOnRails::ClosedConnection.where(rollup: true).count
  end

  test "prune removes transcripts past their own retention" do
    ENV["MAIL_ON_RAILS_TRANSCRIPT_RETENTION_DAYS"] = "7"
    old = MailOnRails::SessionTranscript.record(
      protocol: "smtp", closed_at: 8.days.ago, transcript: "old"
    )
    fresh = MailOnRails::SessionTranscript.record(
      protocol: "smtp", closed_at: 1.day.ago, transcript: "fresh"
    )
    MailOnRails::SessionTranscript.prune!
    assert_nil MailOnRails::SessionTranscript.find_by(id: old.id)
    assert MailOnRails::SessionTranscript.find_by(id: fresh.id)
  end

  test "a transcript failure never loses the history row" do
    # SessionTranscript.record rescues everything into nil; the history
    # row must still land, just unlinked.
    original = MailOnRails::SessionTranscript.method(:record)
    MailOnRails::SessionTranscript.define_singleton_method(:record) { |_info| nil }
    begin
      MailOnRails::ClosedConnection.record(
        close_info(transcript: "<= EHLO", close_reason: "timeout", user: "user@example.test")
      )
    ensure
      MailOnRails::SessionTranscript.define_singleton_method(:record, original)
    end
    connection = MailOnRails::ClosedConnection.where(rollup: false).sole
    assert_equal "user@example.test", connection.username
    assert_nil connection.transcript_id
  end
end
