class Mailbox < ApplicationRecord
  belongs_to :email_account
  has_many :email_messages, dependent: :delete_all

  INBOX = "INBOX"

  # Where infected/unscanned inbound mail is filed for review. Hidden from
  # IMAP LIST (see ImapBackend#list_mailboxes) but an ordinary mailbox
  # otherwise, so the web UI shows it like any other folder.
  QUARANTINE = "Quarantine"

  validates :name, presence: true, uniqueness: { scope: :email_account_id }
  validate :inbox_cannot_be_renamed, on: :update

  before_validation on: :create do
    self.uid_validity ||= Time.current.to_i
  end

  # Inbound delivery files new mail into INBOX (EmailAccount#inbox), so the
  # folder must always exist - except when the whole account is going away.
  before_destroy :prevent_inbox_deletion

  def inbox?
    name == INBOX
  end

  def quarantine?
    name == QUARANTINE
  end

  # Reserves and returns the next UID for a new message.
  def claim_uid!
    with_lock do
      uid = uid_next
      update_columns(uid_next: uid + 1)
      uid
    end
  end

  def unseen_count
    email_messages.where.not("flags LIKE ?", "%Seen%").count
  end

  private

  def inbox_cannot_be_renamed
    errors.add(:name, "INBOX cannot be renamed") if name_changed? && name_was == INBOX
  end

  def prevent_inbox_deletion
    if inbox? && !destroyed_by_association
      errors.add(:base, "INBOX cannot be deleted")
      throw :abort
    end
  end
end
