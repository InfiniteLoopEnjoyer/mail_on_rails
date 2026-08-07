require "test_helper"

# The Prometheus endpoint: enabled only by METRICS_TOKEN, gated on the
# bearer token, and reporting DB-derived series in exposition format.
class MetricsControllerTest < ActionDispatch::IntegrationTest
  TOKEN = "test-metrics-token"

  def with_token(value = TOKEN)
    previous = ENV["METRICS_TOKEN"]
    ENV["METRICS_TOKEN"] = value
    yield
  ensure
    previous ? ENV["METRICS_TOKEN"] = previous : ENV.delete("METRICS_TOKEN")
  end

  def scrape(token: TOKEN)
    get metrics_url, headers: token ? { "Authorization" => "Bearer #{token}" } : {}
  end

  test "the endpoint does not exist without METRICS_TOKEN" do
    with_token(nil) { scrape }
    assert_response :not_found
  end

  test "a missing or wrong bearer token is unauthorized" do
    with_token do
      scrape(token: nil)
      assert_response :unauthorized

      scrape(token: "wrong")
      assert_response :unauthorized
    end
  end

  test "a valid token gets the exposition format without a signed-in session" do
    account = EmailAccount.create!(email: "metrics@example.com", password: "secret123")
    EmailMessage.deliver_raw(account.inbox, "Subject: hi\r\n\r\nbody\r\n")
    SmtpOutboundMessage.create!(mail_from: account.email, recipient: "out@remote.test",
                                data: "raw", next_attempt_at: 1.minute.ago)
    SmtpOutboundMessage.create!(mail_from: account.email, recipient: "sent@remote.test",
                                data: "raw", next_attempt_at: 10.minutes.ago,
                                status: :sent, sent_at: 5.minutes.ago, created_at: 10.minutes.ago)

    with_token { scrape }

    assert_response :success
    assert_match "text/plain", response.content_type
    body = response.body

    assert_includes body, %(mail_on_rails_outbound_queue{status="pending"} 1)
    assert_includes body, %(mail_on_rails_outbound_queue{status="sent"} 1)
    assert_includes body, "mail_on_rails_outbound_due 1"
    assert_includes body, "mail_on_rails_outbound_delivery_seconds_count 1"
    assert_match(/mail_on_rails_outbound_delivery_seconds_sum (?:299|300)\.\d+/, body)
    assert_includes body, "mail_on_rails_accounts 1"
    assert_includes body, "mail_on_rails_messages 1"
    assert_match(/mail_on_rails_storage_used_bytes [1-9]\d*/, body)
    assert_includes body, %(mail_on_rails_live_connections{protocol="smtp"} 0)
    assert_includes body, "# TYPE mail_on_rails_outbound_queue gauge"
  end
end
