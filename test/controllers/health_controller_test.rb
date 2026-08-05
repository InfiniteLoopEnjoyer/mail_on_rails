require "test_helper"
require "mail_on_rails/boot"

class HealthControllerTest < ActionDispatch::IntegrationTest
  teardown do
    ENV.delete("MAIL_ON_RAILS_SERVERS")
  end

  test "up is 200 when the in-process mail servers are not requested" do
    get rails_health_check_path

    assert_response :success
  end

  test "up is down while requested mail servers have not bound their listeners" do
    ENV["MAIL_ON_RAILS_SERVERS"] = "true"

    get rails_health_check_path

    assert_response :internal_server_error
  end
end
