class EmailAccount < ApplicationRecord
  DEFAULT_MAILBOXES = %w[INBOX Sent Drafts Trash Junk].freeze

  has_secure_password
  include GeneratedPassword

  # PBKDF2-SHA256 cost served to SCRAM clients. The heavy derivation runs
  # client-side once per authentication (tens of ms native), but the
  # stored key it produces is offline-crackable if the rows and their
  # encryption key both leak - and 4096, RFC 7677's 2015-era floor, does
  # not slow that attack meaningfully. 100k sits well above MongoDB's 15k
  # SCRAM default while staying unnoticeable at login. Stored per row and
  # served back from there, so existing accounts keep their old cost
  # until the next password change. Keep in step with
  # MailOnRails::Imap::Scram::ITERATIONS.
  SCRAM_ITERATIONS = 100_000

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

  # -- storage quota -----------------------------------------------------------
  # quota_bytes nil = unlimited. used_bytes is maintained incrementally by
  # EmailMessage's create/destroy callbacks (backfilled by migration); it
  # can drift only if a process dies between the message write and the
  # counter bump, and a console re-sum trues it up.

  validates :quota_bytes, numericality: { greater_than: 0 }, allow_nil: true

  def quota_exceeded_by?(bytes)
    quota_bytes.present? && used_bytes + bytes > quota_bytes
  end

  def used_percent
    return nil unless quota_bytes

    (used_bytes * 100.0 / quota_bytes).round
  end

  # The admin form edits the quota in whole megabytes; blank = unlimited.
  def quota_megabytes
    quota_bytes && quota_bytes / 1_048_576
  end

  def quota_megabytes=(value)
    self.quota_bytes = value.present? ? (value.to_f * 1_048_576).round : nil
  end

  # -- vacation autoresponder ----------------------------------------------------

  has_many :vacation_replies, dependent: :delete_all

  validates :vacation_body, presence: true, if: :vacation_enabled
  validate :vacation_dates_ordered

  # Enabled and inside the (optional) date range. A nil bound is open:
  # starts_on nil = already started, ends_on nil = until switched off.
  def vacation_active?
    vacation_enabled &&
      (vacation_starts_on.nil? || Date.current >= vacation_starts_on) &&
      (vacation_ends_on.nil? || Date.current <= vacation_ends_on)
  end

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

  def vacation_dates_ordered
    if vacation_starts_on && vacation_ends_on && vacation_ends_on < vacation_starts_on
      errors.add(:vacation_ends_on, "must not be before the start date")
    end
  end
end
