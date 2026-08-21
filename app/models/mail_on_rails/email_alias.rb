# An extra address that delivers into an existing account's INBOX. An
# alias has no mailboxes and no credentials of its own, and cannot be
# used to send - it exists only as a recipient address: the SMTP server
# accepts it at RCPT time (Store::SmtpBackend#local_rcpts) and the
# mailroom resolves it to its account at delivery time.
module MailOnRails
  class EmailAlias < Record
    belongs_to :email_account

    validates :email, presence: true, uniqueness: { case_sensitive: false }
    validate :email_not_an_account_address

    normalizes :email, with: ->(email) { email.strip.downcase }

    # Turbo broadcasts attach via ActiveSupport.on_load(:mail_on_rails_email_alias).

    private

    # An address can be an account or an alias, never both: the mailroom
    # resolves accounts first, so an alias shadowing an account would
    # silently never receive mail.
    def email_not_an_account_address
      errors.add(:email, "is already an account address") if email.present? && EmailAccount.exists?(email: email)
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_email_alias, MailOnRails::EmailAlias
