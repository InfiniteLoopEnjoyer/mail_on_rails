class EmailAccount < ApplicationRecord
  DEFAULT_MAILBOXES = %w[INBOX Sent Drafts Trash Junk].freeze

  has_secure_password

  has_many :mailboxes, dependent: :destroy

  validates :email, presence: true, uniqueness: { case_sensitive: false }

  normalizes :email, with: ->(email) { email.strip.downcase }

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
end
