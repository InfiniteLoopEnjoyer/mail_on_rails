require "test_helper"
require "mail_on_rails/store"
begin
  require "mail_on_rails/imap/store/contracts"
rescue LoadError
  # The sibling-repo daemon gems (:daemons group) aren't installed, e.g.
  # in CI (BUNDLE_WITHOUT=daemons). The stub below keeps the gap visible.
end

unless defined?(MailOnRails::Imap::Store::Contracts)
  class ImapBackendStoreTest < ActiveSupport::TestCase
    test "imap backend store contract" do
      skip "mail_on_rails_imap gem not installed (BUNDLE_WITHOUT=daemons)"
    end
  end
end

# The Active Record implementation behind the imap HTTP endpoint must
# satisfy the store contract (docs/store_contract.md) - the same suite
# runs against MailOnRails::Imap::Store::Memory in the mail_on_rails_imap gem, and
# against the full HTTP round trip in http_imap_store_test.rb.
if defined?(MailOnRails::Imap::Store::Contracts)
class ImapBackendStoreTest < ActiveSupport::TestCase
  include MailOnRails::Imap::Store::Contracts::Imap

  def create_account(email:, password:)
    EmailAccount.create!(email: email, password: password).id
  end

  def build_store(**)
    MailOnRails::Store::ImapBackend.new
  end
end
end
