# A remote address outbound delivery must skip. Two kinds of row:
#
#   sender NULL   - the recipient reported mail from this server as spam
#                   through a provider feedback loop (ARF to fbl@/jmrp@,
#                   see IngestFblReportJob); ALL outbound mail to them is
#                   suppressed, because continuing to mail them burns the
#                   server's sending reputation with their provider.
#   sender set    - the recipient unsubscribed from one local sender's
#                   list mail (RFC 8058 one-click or the mailto: fallback,
#                   see UnsubscribesController / IngestUnsubscribeJob);
#                   only that sender's mail to them is suppressed.
#
# DeliverSmtpOutboundJob consults this table at delivery time and bounces
# the message back to the local sender instead of attempting delivery.
# Lifting a suppression is deliberate: an operator deletes the row.
module MailOnRails
  class SuppressedRecipient < Record
    validates :email, presence: true, uniqueness: { case_sensitive: false, scope: :sender }

    normalizes :email, with: ->(email) { email.to_s.strip.downcase }
    normalizes :sender, with: ->(sender) { sender.to_s.strip.downcase.presence }

    # Suppressed globally (a sender-NULL row), or - when the prospective
    # sender is given - by that sender's own unsubscribe row.
    def self.suppressed?(address, sender: nil)
      senders = [ nil, normalize_value_for(:sender, sender) ].uniq
      where(email: normalize_value_for(:email, address), sender: senders).exists?
    end

    # Upserts the complainant (global suppression): first complaint creates
    # the row, repeats (providers re-report every message the user junks)
    # bump the count and refresh the latest report metadata.
    def self.record_complaint!(address, feedback_type: nil, reporter: nil)
      record = find_or_create_by!(email: address, sender: nil)
      record.update!(complaints_count: record.complaints_count + 1,
                     last_complaint_at: Time.current,
                     feedback_type: feedback_type.presence || record.feedback_type,
                     reporter: reporter.presence || record.reporter)
      record
    rescue ActiveRecord::RecordNotUnique
      retry
    end

    # Upserts a sender-scoped unsubscribe (idempotent - providers may
    # replay the one-click POST).
    def self.record_unsubscribe!(address, sender:, reporter: nil)
      record = find_or_create_by!(email: address, sender: sender)
      record.update!(complaints_count: record.complaints_count + 1,
                     last_complaint_at: Time.current,
                     feedback_type: "unsubscribe",
                     reporter: reporter.presence || record.reporter)
      record
    rescue ActiveRecord::RecordNotUnique
      retry
    end

    # Upserts a sender-scoped hard bounce (a 5.x.x DSN came back to the
    # VERP address - see IngestBounceJob): the mailbox is gone, so this
    # sender's list mail stops; the operator lifts it if it was transient
    # after all.
    def self.record_bounce!(address, sender:, reporter: nil)
      record = find_or_create_by!(email: address, sender: sender)
      record.update!(complaints_count: record.complaints_count + 1,
                     last_complaint_at: Time.current,
                     feedback_type: "hard-bounce",
                     reporter: reporter.presence || record.reporter)
      record
    rescue ActiveRecord::RecordNotUnique
      retry
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_suppressed_recipient, MailOnRails::SuppressedRecipient
