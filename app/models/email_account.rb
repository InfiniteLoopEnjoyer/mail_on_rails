class EmailAccount < ApplicationRecord
  DEFAULT_MAILBOXES = %w[INBOX Sent Drafts Trash Junk].freeze

  has_secure_password
  include GeneratedPassword

  has_many :mailboxes, dependent: :destroy
  has_many :email_aliases, dependent: :destroy

  validates :email, presence: true, uniqueness: { case_sensitive: false }
  validate :email_not_an_alias_address

  normalizes :email, with: ->(email) { email.strip.downcase }

  # Live-refresh the accounts index and this account's own page (Turbo
  # refresh broadcasts - pages subscribe via turbo_stream_from).
  after_commit -> { broadcast_refresh_later_to :email_accounts }
  after_update_commit -> { broadcast_refresh_later }

  # Keep the exim edge's RCPT-time recipient list (a file on the shared
  # mailconf volume, see EximLocalRecipients) in step with the table.
  # One registration for create/rename/destroy: repeating the same method
  # symbol across after_*_commit macros keeps only the last registration.
  # saved_change_to_email? is also true on create (nil -> address).
  after_commit :sync_exim_recipients, if: -> { destroyed? || saved_change_to_email? }

  after_create :create_default_mailboxes

  def inbox
    mailboxes.find_by(name: "INBOX")
  end

  def find_mailbox(name)
    return mailboxes.find_by("LOWER(name) = 'inbox'") if name.casecmp?("INBOX")

    mailboxes.find_by(name: name)
  end

  # Created on demand: most accounts never receive a flagged message.
  def quarantine_mailbox
    find_mailbox(Mailbox::QUARANTINE) || mailboxes.create!(name: Mailbox::QUARANTINE)
  end

  private

  def create_default_mailboxes
    DEFAULT_MAILBOXES.each { |name| mailboxes.create!(name: name) }
  end

  def sync_exim_recipients
    EximLocalRecipients.sync!
  end

  # Mirror of EmailAlias#email_not_an_account_address - an address can be
  # an account or an alias, never both. Own aliases count too: renaming an
  # account onto one of its aliases would shadow that alias forever.
  def email_not_an_alias_address
    errors.add(:email, "is already in use as an alias") if email.present? && EmailAlias.exists?(email: email)
  end
end
