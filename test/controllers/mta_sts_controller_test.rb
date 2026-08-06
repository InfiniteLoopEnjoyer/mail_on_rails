require "test_helper"

class MtaStsControllerTest < ActionDispatch::IntegrationTest
  test "serves the policy without authentication" do
    ENV["SMTP_HELO_HOST"] = "mail.host.test"
    get "/.well-known/mta-sts.txt"

    assert_response :success
    assert_match %r{\Atext/plain}, response.content_type
    assert_equal "version: STSv1\r\nmode: #{MtaSts::MODE}\r\nmx: mail.host.test\r\nmax_age: #{MtaSts::MAX_AGE}\r\n", response.body
  ensure
    ENV.delete("SMTP_HELO_HOST")
  end

  test "404 when no SMTP hostname is configured" do
    get "/.well-known/mta-sts.txt"

    assert_response :not_found
  end
end
