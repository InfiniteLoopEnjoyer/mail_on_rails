# frozen_string_literal: true

module MailOnRails
  # What a user's filing decision teaches the server. A message filed
  # into Junk - over IMAP from any client, with the web UI's "Mark as
  # spam", or by importing straight into the folder - says "this sender
  # is spam"; one rescued out of Junk into anywhere but Trash says the
  # opposite (Junk -> Trash is just deleting spam). Each signal does two
  # things:
  #
  #   * upserts the account's SenderRule for the message's From address
  #     (deny / allow), which the mailroom applies from the next delivery
  #     on - and flips back on the opposite move, so a mistaken filing is
  #     undone by moving the message back;
  #   * enqueues LearnSpamJob, which trains rspamd's Bayes classifier
  #     (learning the other class unlearns the first, so that is undone
  #     the same way).
  #
  # Only the exact "Junk" folder counts, in either direction: a Junk
  # sub-folder is somewhere the user files things, not a verdict (so
  # Junk -> Junk/2025 is silent, and so is Junk/2025 -> INBOX). The
  # mailroom's own filing into Junk never comes through here - rspamd
  # must not learn from itself.
  #
  # Never raises: callers are the IMAP MOVE/COPY/APPEND handlers and a
  # failure here must not turn a successful move into a NO.
  module JunkFeedback
    module_function

    # `message` is the row in the destination mailbox (`to`); `from` is
    # the mailbox it left, nil for APPEND/import. Returns "spam", "ham"
    # or nil (no signal).
    def filed(message, from:, to:, source:)
      klass = classify(from, to)
      return unless klass

      record_rule(to.email_account, message.from_address, klass == "spam" ? "deny" : "allow", source)
      enqueue_learn(message, klass)
      klass
    rescue StandardError => e
      MailOnRails.logger.error "[mail_on_rails] junk feedback failed for message #{message&.id}: #{e.class}: #{e.message}"
      nil
    end

    def classify(from, to)
      if to.junk?
        "spam" unless from && junk_like?(from)
      elsif from&.junk? && !junk_like?(to) && !to.trash?
        "ham"
      end
    end

    # Junk itself or anything filed beneath it.
    def junk_like?(mailbox)
      mailbox.junk? || mailbox.name.start_with?("#{Mailbox::JUNK}/")
    end

    # No rule without a From, and none on the account's own addresses: a
    # deny on yourself would junk your own forwards, and DMARC already
    # answers self-spoofing.
    def record_rule(account, from_address, verdict, source)
      address = SenderRule.normalize_value_for(:address, from_address)
      return if address.blank? || !address.match?(SenderRule::ADDRESS)
      return if address == account.email || account.email_aliases.exists?(email: address)

      SenderRule.record!(account, address, verdict, source: source)
    end

    # The IMAP backend moves inside a transaction; the job must not be
    # visible to a worker before the row it names is.
    def enqueue_learn(message, klass)
      args = [ message.id, message.email_object_id, message.mailbox.email_account_id, klass ]
      ActiveRecord.after_all_transactions_commit { LearnSpamJob.perform_later(*args) }
    end
  end
end
