require "test_helper"
require "mail_on_rails/store"
require "mail_on_rails/imap/store/contracts"

# The Active Record implementation behind the in-process IMAP server must
# satisfy the store contract (docs/store_contract.md) - the same suite
# runs against MailOnRails::Imap::Store::Memory in the vendored server
# tests (test/vendored/imap).
class ImapBackendStoreTest < ActiveSupport::TestCase
  include MailOnRails::Imap::Store::Contracts::Imap

  def create_account(email:, password:)
    EmailAccount.create!(email: email, password: password).id
  end

  def build_store(**)
    MailOnRails::Store::ImapBackend.new
  end

  test "tombstone pruning raises the floor and expunged_since falls back" do
    raw = MailOnRails::Imap::Store::Contracts::Imap::RAW_CRLF
    uids = 3.times.map { store.append(account_id, "INBOX", raw, [ "\\Deleted" ], nil)[:uid] }
    mailbox = Mailbox.find(store.select_mailbox(account_id, "INBOX")[:mailbox_id])

    uids.each { |uid| store.expunge(mailbox.id, [ uid ]) }
    ExpungedMessage.prune!(mailbox, limit: 2)
    mailbox.reload

    assert_operator mailbox.tombstone_floor, :>, 0
    assert_equal 2, mailbox.expunged_messages.count

    result = store.expunged_since(mailbox.id, 0)
    refute result[:complete]
    assert_equal uids.sort, result[:uids].sort, "fallback must cover every missing uid"

    recent = store.expunged_since(mailbox.id, mailbox.tombstone_floor)
    assert recent[:complete]
    assert_equal uids.last(2).sort, recent[:uids].sort
  end
end
