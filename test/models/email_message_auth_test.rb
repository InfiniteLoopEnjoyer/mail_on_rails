require "test_helper"

class EmailMessageAuthTest < ActiveSupport::TestCase
  test "sender_verified? accepts authenticated submitters" do
    assert EmailMessage.new(authenticated_as: "tayden@example.test").sender_verified?
  end

  test "sender_verified? accepts dmarc pass" do
    message = EmailMessage.new(auth_results: "spf=fail; dkim=none; dmarc=pass header.from=example.com")
    assert message.sender_verified?
    assert_equal "pass", message.auth_result("dmarc")
    assert_equal "fail", message.auth_result("spf")
  end

  test "sender_verified? rejects everything else" do
    assert_not EmailMessage.new(auth_results: "spf=pass; dkim=pass; dmarc=fail").sender_verified?
    assert_not EmailMessage.new.sender_verified?
  end
end
