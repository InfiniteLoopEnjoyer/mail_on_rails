require "test_helper"

# The endpoints the mail edges call - the Action Mailbox relay ingress and the
# internal API - are fronted by a local-only routing constraint
# (config/routes.rb): clients whose resolved remote_ip is not loopback/private
# get a 404, as only the edges on the docker network should ever reach them.
class EdgeEndpointsLocalOnlyTest < ActionDispatch::IntegrationTest
  EDGE_PATHS = [
    "/rails/action_mailbox/relay/inbound_emails",
    "/mail_on_rails/internal/authenticate",
    "/mail_on_rails/internal/outbound_messages",
    "/mail_on_rails/internal/imap/select"
  ]

  test "public clients are 404ed before reaching any edge endpoint" do
    EDGE_PATHS.each do |path|
      post path, headers: { "REMOTE_ADDR" => "203.0.113.9" }
      assert_response :not_found
    end
  end

  test "a spoofed private X-Forwarded-For from a public client is still 404ed" do
    EDGE_PATHS.each do |path|
      post path, headers: {
        "REMOTE_ADDR" => "172.18.0.2", # what puma sees: the proxy itself
        "X-Forwarded-For" => "172.18.0.5, 203.0.113.9" # spoofed private + real IP appended by kamal-proxy
      }
      assert_response :not_found
    end
  end

  test "docker-network clients fall through to the password auth" do
    EDGE_PATHS.each do |path|
      post path, headers: { "REMOTE_ADDR" => "172.18.0.5" }
      assert_response :unauthorized
    end
  end

  test "loopback clients fall through to the password auth" do
    EDGE_PATHS.each do |path|
      post path
      assert_response :unauthorized
    end
  end
end
