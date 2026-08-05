# Empties old mail out of every account's Trash (recurring, see
# config/recurring.yml). Only Trash - everything else is kept forever. The
# clock starts when the message entered Trash: moving creates a fresh row
# (new UID, IMAP MOVE semantics), so its created_at is the move time, not
# the received date. Rows go through destroy! so each expunge leaves the
# tombstone IMAP clients need for VANISHED catch-up.
class PurgeTrashJob < ApplicationJob
  queue_as :default

  def perform
    cutoff = Setting.trash_retention_days.days.ago

    Mailbox.where(name: Mailbox::TRASH).find_each do |trash|
      trash.email_messages.where(created_at: ...cutoff).find_each do |message|
        message.destroy!
        Rails.logger.info "[mail_on_rails] purged trash message #{message.id} " \
                          "(#{trash.email_account.email}, trashed #{message.created_at.to_date})"
      end
    end
  end
end
