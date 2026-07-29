require "test_helper"

class MailOnRails::InternalControllerTest < ActionDispatch::IntegrationTest
  EMAIL = "api@example.test"
  PASSWORD = "api-pass-12345"

  setup do
    @account = EmailAccount.create!(email: EMAIL, password: PASSWORD)
  end

  def api_auth
    password = ENV["SMTP_INTERNAL_API_PASSWORD"].presence ||
               Rails.application.credentials.dig(:mail_on_rails, :internal_api_password)
    { "Authorization" => ActionController::HttpAuthentication::Basic.encode_credentials("mail_on_rails", password) }
  end

  test "rejects requests without the api password" do
    post mail_on_rails_internal_authenticate_path, params: { email: EMAIL, password: PASSWORD }, as: :json
    assert_response :unauthorized

    post mail_on_rails_internal_authenticate_path,
         params: { email: EMAIL, password: PASSWORD }, as: :json,
         headers: { "Authorization" => ActionController::HttpAuthentication::Basic.encode_credentials("mail_on_rails", "wrong") }
    assert_response :unauthorized
  end

  test "authenticate returns the account for good credentials and nulls for bad" do
    post mail_on_rails_internal_authenticate_path, params: { email: " #{EMAIL.upcase} ", password: PASSWORD },
                                               as: :json, headers: api_auth
    assert_response :success
    assert_equal({ "account_id" => @account.id, "email" => EMAIL }, response.parsed_body)

    post mail_on_rails_internal_authenticate_path, params: { email: EMAIL, password: "wrong" },
                                               as: :json, headers: api_auth
    assert_response :success
    assert_equal({ "account_id" => nil, "email" => nil }, response.parsed_body)
  end

  def authenticate_as(password:, ip: "203.0.113.9")
    post mail_on_rails_internal_authenticate_path,
         params: { email: EMAIL, password: password, ip: ip }, as: :json, headers: api_auth
    response.parsed_body
  end

  test "authenticate throttles after repeated failures and reports retry_after" do
    original = ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"]
    ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"] = "3"

    3.times { assert_nil authenticate_as(password: "wrong")["throttled"] }

    blocked = authenticate_as(password: "wrong")
    assert blocked["throttled"]
    assert_operator blocked["retry_after"], :>, 0
    assert_nil blocked["account_id"]

    # The block outranks a correct password - that is the point.
    assert authenticate_as(password: PASSWORD)["throttled"]
  ensure
    original ? ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"] = original
             : ENV.delete("MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES")
  end

  test "a successful authenticate clears the account's failure counter" do
    2.times { authenticate_as(password: "wrong") }
    assert AuthThrottle.find_by(scope: "account", key: EMAIL)

    assert_equal @account.id, authenticate_as(password: PASSWORD)["account_id"]
    assert_nil AuthThrottle.find_by(scope: "account", key: EMAIL)
  end

  test "authenticate without an ip still counts the account scope" do
    post mail_on_rails_internal_authenticate_path,
         params: { email: EMAIL, password: "wrong" }, as: :json, headers: api_auth
    assert_response :success
    assert AuthThrottle.find_by(scope: "account", key: EMAIL)
    assert_nil AuthThrottle.find_by(scope: "ip")
  end

  test "a failed authenticate is logged with the edge's source" do
    post mail_on_rails_internal_authenticate_path,
         params: { email: EMAIL, password: "wrong", ip: "203.0.113.9", source: "smtp" },
         as: :json, headers: api_auth
    assert_response :success

    attempt = AuthAttempt.sole
    assert_equal "smtp", attempt.source
    assert_equal "203.0.113.9", attempt.ip
    assert_equal EMAIL, attempt.username
    assert_equal "bad_credentials", attempt.outcome
    assert attempt.account_exists, "this address does exist here"
  end

  test "an attempt on an address that does not exist is logged as unknown_account" do
    post mail_on_rails_internal_authenticate_path,
         params: { email: "cyrus", password: "wrong", ip: "203.0.113.9", source: "smtp" },
         as: :json, headers: api_auth

    attempt = AuthAttempt.sole
    assert_equal "unknown_account", attempt.outcome
    assert_not attempt.account_exists
  end

  test "a successful authenticate is not logged" do
    post mail_on_rails_internal_authenticate_path,
         params: { email: EMAIL, password: PASSWORD, ip: "203.0.113.9", source: "smtp" },
         as: :json, headers: api_auth
    assert_response :success
    assert_equal 0, AuthAttempt.count, "successes would bury the signal"
  end

  # An edge names itself, but the label is only accepted from a known set -
  # otherwise a caller could invent sources and poison the analysis.
  test "an unrecognised source is dropped rather than stored" do
    post mail_on_rails_internal_authenticate_path,
         params: { email: EMAIL, password: "wrong", ip: "203.0.113.9", source: "../../etc" },
         as: :json, headers: api_auth
    assert_response :success
    assert_equal 0, AuthAttempt.count
  end

  test "an omitted source is not logged either" do
    post mail_on_rails_internal_authenticate_path,
         params: { email: EMAIL, password: "wrong", ip: "203.0.113.9" },
         as: :json, headers: api_auth
    assert_response :success
    assert_equal 0, AuthAttempt.count, "a row labelled with a guessed source is worse than none"
    assert AuthThrottle.find_by(scope: "account", key: EMAIL), "...but it still counts for throttling"
  end

  test "imap record_auth_failure logs with the imap source" do
    post "/mail_on_rails/internal/imap/record_auth_failure",
         params: { email: EMAIL, ip: "203.0.113.9", source: "imap" }, as: :json, headers: api_auth

    assert_equal "imap", AuthAttempt.sole.source
  end

  test "imap record_auth_failure counts a failure the daemon adjudicated" do
    post "/mail_on_rails/internal/imap/record_auth_failure",
         params: { email: EMAIL, ip: "203.0.113.9" }, as: :json, headers: api_auth
    assert_response :success

    assert_equal 1, AuthThrottle.find_by(scope: "account", key: EMAIL).failure_count
    assert_equal 1, AuthThrottle.find_by(scope: "ip", key: "203.0.113.9").failure_count
  end

  test "imap scram_credentials is refused while throttled" do
    original = ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"]
    ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"] = "1"
    authenticate_as(password: "wrong")

    post "/mail_on_rails/internal/imap/scram_credentials",
         params: { email: EMAIL, ip: "203.0.113.9" }, as: :json, headers: api_auth
    assert_response :success
    body = response.parsed_body
    assert body["throttled"], "verifier material must not be handed out mid-block"
    assert_nil body["salt_base64"]
  ensure
    original ? ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"] = original
             : ENV.delete("MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES")
  end

  test "outbound_messages queues one row per recipient" do
    raw = "From: #{EMAIL}\r\nSubject: out\r\n\r\nbody\r\n"
    assert_difference -> { SmtpOutboundMessage.count }, 2 do
      post "#{mail_on_rails_internal_outbound_messages_path}?#{{ mail_from: EMAIL, rcpt: [ "a@remote.test", "b@remote.test" ] }.to_query}",
           params: raw, headers: api_auth.merge("Content-Type" => "message/rfc822")
    end
    assert_response :created

    message = SmtpOutboundMessage.order(:id).last
    assert_equal EMAIL, message.mail_from
    assert_equal "b@remote.test", message.recipient
    assert_equal raw, message.data
    assert message.pending?
  end

  test "outbound_messages enforces the queue cap with 507" do
    original = ENV["MAIL_ON_RAILS_OUTBOUND_LIMIT"]
    ENV["MAIL_ON_RAILS_OUTBOUND_LIMIT"] = "1"
    post "#{mail_on_rails_internal_outbound_messages_path}?#{{ mail_from: EMAIL, rcpt: [ "a@remote.test", "b@remote.test" ] }.to_query}",
         params: "raw", headers: api_auth.merge("Content-Type" => "message/rfc822")
    assert_response :insufficient_storage
    assert_equal 0, SmtpOutboundMessage.count
  ensure
    original ? ENV["MAIL_ON_RAILS_OUTBOUND_LIMIT"] = original : ENV.delete("MAIL_ON_RAILS_OUTBOUND_LIMIT")
  end

  test "outbound_messages rejects empty recipients or body" do
    post "#{mail_on_rails_internal_outbound_messages_path}?mail_from=#{EMAIL}",
         params: "raw", headers: api_auth.merge("Content-Type" => "message/rfc822")
    assert_response :unprocessable_entity

    post "#{mail_on_rails_internal_outbound_messages_path}?#{{ mail_from: EMAIL, rcpt: [ "a@remote.test" ] }.to_query}",
         headers: api_auth.merge("Content-Type" => "message/rfc822")
    assert_response :unprocessable_entity
  end
end
