module MailOnRails
  class Mailbox < Record
    belongs_to :email_account
    has_many :email_messages, dependent: :delete_all
    has_many :expunged_messages, dependent: :delete_all

    INBOX = "INBOX"

    # Where infected/unscanned inbound mail is filed for review. Hidden from
    # IMAP LIST (see ImapBackend#list_mailboxes) but an ordinary mailbox
    # otherwise, so the web UI shows it like any other folder.
    QUARANTINE = "Quarantine"

    # Where rspamd-flagged inbound mail is filed instead of INBOX, and where
    # the web UI's "Mark as spam" moves a message.
    JUNK = "Junk"

    # Where the web UI's "Delete" moves a message; deleting inside Trash is
    # permanent.
    TRASH = "Trash"

    validates :name, presence: true, uniqueness: { scope: :email_account_id }
    validate :inbox_cannot_be_renamed, on: :update

    before_validation on: :create do
      self.uid_validity ||= Time.current.to_i
    end

    # Turbo broadcasts attach via ActiveSupport.on_load(:mail_on_rails_mailbox).

    # Inbound delivery files new mail into INBOX (EmailAccount#inbox), so the
    # folder must always exist - except when the whole account is going away.
    before_destroy :prevent_inbox_deletion

    def inbox?
      name == INBOX
    end

    def quarantine?
      name == QUARANTINE
    end

    def junk?
      name == JUNK
    end

    def trash?
      name == TRASH
    end

    # Reserves and returns the next UID for a new message.
    #
    # with_lock is SELECT ... FOR UPDATE on PostgreSQL and MySQL/InnoDB.
    # SQLite's adapter ignores the FOR UPDATE, but Rails opens its write
    # transactions in IMMEDIATE mode (single writer), so the
    # read-increment-write here is still serialized.
    def claim_uid!
      with_lock do
        uid = uid_next
        update_columns(uid_next: uid + 1)
        uid
      end
    end

    # Advances and returns the mailbox's mod-sequence (RFC 7162 CONDSTORE).
    # Every content mutation - delivery, flag change, expunge - claims one.
    def claim_modseq!
      with_lock do
        seq = highest_modseq + 1
        update_columns(highest_modseq: seq)
        seq
      end
    end

    # Substring prefilter over the JSON-serialized flags column; no
    # metacharacters, so it is portable. MySQL/SQLite match it
    # case-insensitively, which for IMAP flags (RFC 3501: case-insensitive
    # atoms) is at least as correct as PostgreSQL's case-sensitive LIKE.
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
end

ActiveSupport.run_load_hooks :mail_on_rails_mailbox, MailOnRails::Mailbox
