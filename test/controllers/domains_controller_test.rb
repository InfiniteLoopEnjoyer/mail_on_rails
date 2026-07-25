require "test_helper"

class DomainsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    # No MAIL_ON_RAILS_DKIM_DIR / MAIL_ON_RAILS_EXIM_DOMAINS_FILE in test:
    # key generation and exim sync are no-ops (covered in the model test).
    @domain = Domain.create!(name: "example.com")
  end

  test "requires authentication" do
    sign_out
    get domains_url
    assert_redirected_to new_session_url
  end

  test "index lists domains" do
    get domains_url
    assert_response :success
    assert_select ".primary", text: @domain.name
  end

  test "creates a domain" do
    assert_difference "Domain.count", 1 do
      post domains_url, params: { domain: { name: "example.org" } }
    end
    assert_redirected_to domain_url(Domain.find_by(name: "example.org"))
  end

  test "rejects an invalid name" do
    assert_no_difference "Domain.count" do
      post domains_url, params: { domain: { name: "not a domain" } }
    end
    assert_response :unprocessable_entity
  end

  test "show renders the DNS records" do
    get domain_url(@domain)
    assert_response :success
    assert_match "rail._domainkey.example.com", response.body
    assert_match "v=spf1 mx -all", response.body
  end

  test "destroys a domain" do
    assert_difference "Domain.count", -1 do
      delete domain_url(@domain)
    end
    assert_redirected_to domains_url
  end
end
