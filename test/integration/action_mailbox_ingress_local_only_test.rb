require "test_helper"

# The relay ingress is fronted by a routing constraint (config/routes.rb) that
# 404s any client whose resolved remote_ip is not loopback/private - only the
# exim edge on the docker network should ever reach it.
class ActionMailboxIngressLocalOnlyTest < ActionDispatch::IntegrationTest
  INGRESS_PATH = "/rails/action_mailbox/relay/inbound_emails"

  test "public clients are 404ed before reaching the ingress" do
    post INGRESS_PATH, headers: { "REMOTE_ADDR" => "203.0.113.9" }
    assert_response :not_found
  end

  test "a spoofed private X-Forwarded-For from a public client is still 404ed" do
    post INGRESS_PATH, headers: {
      "REMOTE_ADDR" => "172.18.0.2", # what puma sees: the proxy itself
      "X-Forwarded-For" => "172.18.0.5, 203.0.113.9" # spoofed private + real IP appended by kamal-proxy
    }
    assert_response :not_found
  end

  test "docker-network clients fall through to the real ingress" do
    post INGRESS_PATH, headers: { "REMOTE_ADDR" => "172.18.0.5" }
    assert_response :unauthorized
  end

  test "loopback clients fall through to the real ingress" do
    post INGRESS_PATH
    assert_response :unauthorized
  end
end
