require "test_helper"
require "mail_on_rails/store"
begin
  require "mail_on_rails/imap/store/http"
  require "mail_on_rails/imap/store/contracts"
rescue LoadError
  # The sibling-repo daemon gems (:daemons group) aren't installed, e.g.
  # in CI (BUNDLE_WITHOUT=daemons). The stub below keeps the gap visible.
end

unless defined?(MailOnRails::Imap::Store::Contracts)
  class HttpImapStoreTest < ActiveSupport::TestCase
    test "http imap store contract" do
      skip "mail_on_rails_imap gem not installed (BUNDLE_WITHOUT=daemons)"
    end
  end
end

# The full IMAP store contract, driven through the real HTTP stack:
# the daemon store's payload framing -> routes -> MailOnRails::InternalController
# -> Store::ImapBackend -> Postgres, with responses decoded exactly as
# the daemon's client decodes them (InternalApi.decode_store_result).
# Only Net::HTTP itself is bypassed - Rack integration requests stand in
# for the socket, which the smtp path and the e2e smoke cover.
if defined?(MailOnRails::Imap::Store::Contracts)
class HttpImapStoreTest < ActionDispatch::IntegrationTest
  include MailOnRails::Imap::Store::Contracts::Imap

  # InternalApi's interface, transported over integration-test requests.
  class RackApi
    def initialize(test)
      @test = test
      password = Rails.application.credentials.dig(:mail_on_rails, :internal_api_password)
      @headers = { "Authorization" => ActionController::HttpAuthentication::Basic.encode_credentials("mail_on_rails", password) }
    end

    def authenticate(email, password)
      body = post("/mail_on_rails/internal/authenticate", { email: email, password: password })
      { account_id: body[:account_id], email: body[:email] }
    end

    def imap_op(op, payload)
      MailOnRails::Imap::InternalApi.decode_store_result(post("/mail_on_rails/internal/imap/#{op}", payload))
    end

    private

    def post(path, payload)
      @test.post path, params: payload, as: :json, headers: @headers
      raise "#{path} => #{@test.response.status}" unless @test.response.successful?

      JSON.parse(@test.response.body, symbolize_names: true)
    end
  end

  def build_store(**)
    MailOnRails::Imap::Store::Http.new(api: RackApi.new(self), logger: Rails.logger)
  end

  def create_account(email:, password:)
    EmailAccount.create!(email: email, password: password).id
  end

  test "unknown operations 404 and surface as the internal envelope" do
    result = store.list_mailboxes(account_id) # warm: proves the store works
    assert result[:mailboxes]

    post "/mail_on_rails/internal/imap/drop_table", params: {}, as: :json,
         headers: { "Authorization" => ActionController::HttpAuthentication::Basic.encode_credentials(
           "mail_on_rails", Rails.application.credentials.dig(:mail_on_rails, :internal_api_password)
         ) }
    assert_response :not_found
  end

  test "raw bytes survive the base64 framing byte for byte" do
    binary = "From: a@b.test\r\nSubject: bin\r\n\r\n\x00\xFF\x01binary body\x80\r\n".b
    uid = store.append(account_id, "INBOX", binary, [], nil)[:uid]
    mailbox_id = store.select_mailbox(account_id, "INBOX")[:mailbox_id]

    fetched = store.fetch(mailbox_id, [ uid ], true)[:messages].first[:raw]
    assert_equal binary, fetched.b
  end
end

end
