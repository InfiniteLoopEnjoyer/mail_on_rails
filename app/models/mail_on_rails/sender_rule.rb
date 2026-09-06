# frozen_string_literal: true

# A per-account verdict on a sender, keyed by the visible From address
# (or a whole domain, written "@example.com"):
#
#   deny   - the mailroom files the sender's mail into Junk regardless of
#            rspamd's score.
#   allow  - the mailroom delivers to INBOX even when rspamd calls it
#            spam, unless the message failed DMARC (an allowlisted From
#            is exactly what a phisher forges, so authentication still
#            has the last word).
#
# Rows are written automatically by JunkFeedback when a message is filed
# into Junk (deny) or rescued out of it (allow) - over IMAP from any
# client, or with the web UI's "Mark as spam"/"Not spam" - and by hand
# from the account page. Automatic rules are always the exact address;
# only a person can write a domain wildcard. An exact rule beats the
# domain's wildcard.
module MailOnRails
  class SenderRule < Record
    VERDICTS = %w[allow deny].freeze

    # local@domain or @domain; the domain needs at least one dot; no
    # whitespace (which also refuses CR/LF and display names).
    ADDRESS = /\A[^@\s]*@[^@\s.]+(?:\.[^@\s.]+)+\z/

    belongs_to :email_account

    normalizes :address, with: ->(address) { address.to_s.strip.downcase }

    validates :address, presence: true, format: { with: ADDRESS, message: "must be an address or @domain" },
                        uniqueness: { scope: :email_account_id }
    validates :verdict, inclusion: { in: VERDICTS }
    validates :source, presence: true

    # Turbo broadcasts attach via ActiveSupport.on_load(:mail_on_rails_sender_rule).

    def wildcard?
      address.start_with?("@")
    end

    def allow? = verdict == "allow"
    def deny? = verdict == "deny"

    # :allow, :deny or nil for the given From address: the exact address
    # first, then its "@domain" wildcard. One query.
    def self.verdict_for(account, from_address)
      address = normalize_value_for(:address, from_address)
      return nil if address.blank? || !address.include?("@") || address.start_with?("@")

      wildcard = "@#{address.split("@", 2).last}"
      rows = where(email_account_id: account.id, address: [ address, wildcard ]).pluck(:address, :verdict).to_h
      (rows[address] || rows[wildcard])&.to_sym
    end

    # Upsert: the first call creates the row, a repeat flips verdict and
    # source in place (moving a message back out of Junk turns its deny
    # into an allow). The create runs in a savepoint so a lost race inside
    # a caller's transaction (the IMAP backend moves under one) can be
    # retried without poisoning it on PostgreSQL. InnoDB reports the same
    # race as a deadlock between the racing inserts' index locks rather
    # than a duplicate key - same answer, retry. A third spelling of the
    # same race: the loser commits between our lookup and our insert's
    # uniqueness validation, which then fails before the database ever
    # sees the duplicate. Only that one validation error is retried;
    # every other RecordInvalid (a bad verdict, a malformed address) is
    # the caller's and propagates.
    def self.record!(account, address, verdict, source:)
      rule = transaction(requires_new: true) do
        find_or_create_by!(email_account: account, address: normalize_value_for(:address, address)) do |row|
          row.verdict = verdict
          row.source = source
        end
      end
      rule.update!(verdict: verdict, source: source) if rule.verdict != verdict || rule.source != source
      rule
    rescue ActiveRecord::RecordNotUnique, ActiveRecord::Deadlocked
      retry
    rescue ActiveRecord::RecordInvalid => e
      raise unless e.record.errors.size == 1 && e.record.errors.of_kind?(:address, :taken)

      retry
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_sender_rule, MailOnRails::SenderRule
