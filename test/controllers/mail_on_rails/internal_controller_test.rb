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

    post mail_on_rails_internal_rcpt_check_path,
         params: { addresses: [ EMAIL ] }, as: :json,
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

  test "rcpt_check returns the known normalized subset" do
    post mail_on_rails_internal_rcpt_check_path,
         params: { addresses: [ " #{EMAIL.upcase} ", "stranger@example.test" ] },
         as: :json, headers: api_auth
    assert_response :success
    assert_equal({ "local" => [ EMAIL ] }, response.parsed_body)
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
