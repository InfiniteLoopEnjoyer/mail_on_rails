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

  # The captured-sessions table on the live pages.
  test "recent_list is one protocol's captures in the window, newest first" do
    old = MailOnRails::SessionTranscript.record(protocol: "smtp", closed_at: 3.days.ago, transcript: "old")
    late = MailOnRails::SessionTranscript.record(protocol: "smtp", closed_at: 1.hour.ago, transcript: "late")
    early = MailOnRails::SessionTranscript.record(protocol: "smtp", closed_at: 2.hours.ago, transcript: "early")
    MailOnRails::SessionTranscript.record(protocol: "imap", closed_at: 1.minute.ago, transcript: "imap")

    assert_equal [ late.id, early.id ], MailOnRails::SessionTranscript.recent_list(:smtp, since: 1.day.ago).pluck(:id)
    assert_equal [ late.id ], MailOnRails::SessionTranscript.recent_list(:smtp, since: 1.day.ago, limit: 1).pluck(:id)
    assert_includes MailOnRails::SessionTranscript.recent_list("smtp", since: 7.days.ago).pluck(:id), old.id
  end

  test "preview is the peer's first commands, server replies left out, cut to length" do
    capture = MailOnRails::SessionTranscript.new(
      transcript: "=> 220 mx ready\n<= EHLO scanner.test\n=> 250 OK\n<= AUTH LOGIN\n=> 503\n<=   \n<= GET / HTTP/1.1\n<= QUIT"
    )
    assert_equal "EHLO scanner.test · AUTH LOGIN · GET / HTTP/1.1", capture.preview
    assert_equal 8, capture.line_count

    long = MailOnRails::SessionTranscript.new(transcript: "<= #{"A" * 300}")
    assert_equal MailOnRails::SessionTranscript::PREVIEW_CHARS, long.preview.length
    assert long.preview.end_with?("…")

    assert_equal "", MailOnRails::SessionTranscript.new(transcript: "=> 220 only server").preview
    assert_equal 0, MailOnRails::SessionTranscript.new(transcript: nil).line_count
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
