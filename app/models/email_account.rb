class EmailAccount < ApplicationRecord
  DEFAULT_MAILBOXES = %w[INBOX Sent Drafts Trash Junk].freeze

  has_secure_password
  include GeneratedPassword

  SCRAM_ITERATIONS = 4096 # RFC 7677 minimum; the heavy PBKDF2 runs client-side

  # The stored/server keys are password-verifier material - not the
  # password, but worth encrypting at rest like otp_secret.
  encrypts :scram_stored_key, :scram_server_key

  # Derived while the plaintext is available at password-set time; bcrypt
  # digests can't be converted, so pre-existing accounts keep nil (and
  # can't use AUTH=SCRAM-SHA-256) until their next password change.
  before_save :derive_scram_credentials, if: -> { password.present? }

  has_many :mailboxes, dependent: :destroy
  has_many :email_aliases, dependent: :destroy

  validates :email, presence: true, uniqueness: { case_sensitive: false }
  validate :email_not_an_alias_address

  normalizes :email, with: ->(email) { email.strip.downcase }

  # Live-refresh the accounts index and this account's own page (Turbo
  # refresh broadcasts - pages subscribe via turbo_stream_from).
  after_commit -> { broadcast_refresh_later_to :email_accounts }
  after_update_commit -> { broadcast_refresh_later }

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

  # Junk is a default mailbox, but it is deletable - recreate rather than
  # bounce spam into INBOX when it is gone.
  def junk_mailbox
    find_mailbox(Mailbox::JUNK) || mailboxes.create!(name: Mailbox::JUNK)
  end

  # Same recreate-on-demand as Junk: Trash is deletable, and "Delete" must
  # always have somewhere to move the message.
  def trash_mailbox
    find_mailbox(Mailbox::TRASH) || mailboxes.create!(name: Mailbox::TRASH)
  end

  private

  # SCRAM-SHA-256 (RFC 5802/7677): StoredKey = H(HMAC(SaltedPassword,
  # "Client Key")), ServerKey = HMAC(SaltedPassword, "Server Key").
  def derive_scram_credentials
    salt = SecureRandom.random_bytes(16)
    salted = OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: SCRAM_ITERATIONS,
                                      length: 32, hash: "SHA256")
    client_key = OpenSSL::HMAC.digest("SHA256", salted, "Client Key")
    self.scram_salt = [ salt ].pack("m0")
    self.scram_iterations = SCRAM_ITERATIONS
    self.scram_stored_key = [ OpenSSL::Digest.digest("SHA256", client_key) ].pack("m0")
    self.scram_server_key = [ OpenSSL::HMAC.digest("SHA256", salted, "Server Key") ].pack("m0")
  end

  def create_default_mailboxes
    DEFAULT_MAILBOXES.each { |name| mailboxes.create!(name: name) }
  end

  # Mirror of EmailAlias#email_not_an_account_address - an address can be
  # an account or an alias, never both. Own aliases count too: renaming an
  # account onto one of its aliases would shadow that alias forever.
  def email_not_an_alias_address
    errors.add(:email, "is already in use as an alias") if email.present? && EmailAlias.exists?(email: email)
  end
end
