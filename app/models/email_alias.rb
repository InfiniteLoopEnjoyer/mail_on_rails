# An extra address that delivers into an existing account's INBOX. An
# alias has no mailboxes and no credentials of its own, and cannot be
# used to send - it exists only as a recipient address: it is written
# into the exim local_recipients file (so RCPT accepts it) and resolved
# to its account by the mailroom at delivery time.
class EmailAlias < ApplicationRecord
  belongs_to :email_account

  validates :email, presence: true, uniqueness: { case_sensitive: false }
  validate :email_not_an_account_address

  normalizes :email, with: ->(email) { email.strip.downcase }

  # The account page renders its aliases, so alias changes refresh it the
  # same way the account's own changes do. Skipped when the account itself
  # is being destroyed (dependent: :destroy) - nothing left to render.
  after_commit -> { email_account.broadcast_refresh_later unless email_account.destroyed? }

  # Same contract as EmailAccount#sync_exim_recipients: the RCPT-time
  # recipient list must contain aliases too, or exim 550s them.
  after_commit :sync_exim_recipients, if: -> { destroyed? || saved_change_to_email? }

  private

  # An address can be an account or an alias, never both: the mailroom
  # resolves accounts first, so an alias shadowing an account would
  # silently never receive mail.
  def email_not_an_account_address
    errors.add(:email, "is already an account address") if email.present? && EmailAccount.exists?(email: email)
  end

  def sync_exim_recipients
    EximLocalRecipients.sync!
  end
end
