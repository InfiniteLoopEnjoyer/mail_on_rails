require "test_helper"

# The mail servers run in-process and hand inbound mail to Action Mailbox
# directly (Store::SmtpBackend), so no HTTP ingress exists: the Action
# Mailbox routes are pinned closed in config/routes.rb and the old
# internal API is gone entirely. Every client - local or public - gets the
# same 404 an unknown path would.
class EdgeEndpointsLocalOnlyTest < ActionDispatch::IntegrationTest
  RETIRED_PATHS = [
    "/rails/action_mailbox/relay/inbound_emails",
    "/mail_on_rails/internal/authenticate",
    "/mail_on_rails/internal/outbound_messages",
    "/mail_on_rails/internal/imap/select"
  ]

  test "public clients are 404ed" do
    RETIRED_PATHS.each do |path|
      post path, headers: { "REMOTE_ADDR" => "203.0.113.9" }
      assert_response :not_found
    end
  end

  test "local clients are 404ed too - the ingress era is over" do
    RETIRED_PATHS.each do |path|
      post path
      assert_response :not_found

      post path, headers: { "REMOTE_ADDR" => "172.18.0.5" }
      assert_response :not_found
    end
  end
end
