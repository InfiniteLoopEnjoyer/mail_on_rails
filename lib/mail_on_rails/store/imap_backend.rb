# frozen_string_literal: true

module MailOnRails
  module Store
    # The app-side implementation of the IMAP store contract: everything
    # the IMAP server is allowed to do, on Active Record. The daemon never
    # loads this - it talks to MailOnRails::InternalController, which
    # delegates here (see docs/store_contract.md and Store::Imap, the HTTP
    # client the daemon actually uses).
    class ImapBackend < Base
      def list_mailboxes(account_id)
        db do
          account = EmailAccount.find(account_id)
          { mailboxes: account.mailboxes.order(:name).pluck(:name) }
        end
      end

      def create_mailbox(account_id, name)
        db do
          account = EmailAccount.find(account_id)
          next { error: "mailbox exists", code: :exists } if account.find_mailbox(name)

          account.mailboxes.create!(name: name)
          {}
        end
      end

      def select_mailbox(account_id, name)
        db do
          mailbox = EmailAccount.find(account_id).find_mailbox(name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          messages = mailbox.email_messages.order(:uid).map { |m| [ m.uid, m.flags ] }
          {
            mailbox_id: mailbox.id,
            name: mailbox.name,
            uid_validity: mailbox.uid_validity,
            uid_next: mailbox.uid_next,
            messages: messages
          }
        end
      end

      def status(account_id, name)
        db do
          mailbox = EmailAccount.find(account_id).find_mailbox(name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          {
            messages: mailbox.email_messages.count,
            unseen: mailbox.unseen_count,
            uid_next: mailbox.uid_next,
            uid_validity: mailbox.uid_validity
          }
        end
      end

      # Returns per-message metadata for the given UIDs; raw message bytes are
      # included only when requested (they can be large).
      def fetch(mailbox_id, uids, with_raw)
        db do
          scope = EmailMessage.where(mailbox_id: mailbox_id, uid: uids).order(:uid)
          messages = scope.map do |m|
            entry = {
              uid: m.uid,
              flags: m.flags,
              internal_date: m.internal_date.to_i,
              size: m.size
            }
            entry[:raw] = m.raw.to_s if with_raw
            entry
          end
          { messages: messages }
        end
      end

      # mode: "+" adds, "-" removes, "=" replaces.
      def store_flags(mailbox_id, uids, mode, flags)
        db do
          updated = EmailMessage.where(mailbox_id: mailbox_id, uid: uids).map do |m|
            new_flags =
              case mode
              when "+" then (m.flags | flags)
              when "-" then (m.flags - flags)
              else flags
              end
            m.update!(flags: new_flags)
            [ m.uid, new_flags ]
          end
          { messages: updated }
        end
      end

      def expunge(mailbox_id)
        db do
          deleted = EmailMessage.where(mailbox_id: mailbox_id)
                                .where("flags LIKE ?", "%\\\\Deleted%")
                                .order(:uid)
          uids = deleted.map(&:uid)
          deleted.destroy_all
          { uids: uids }
        end
      end

      def append(account_id, mailbox_name, raw, flags, internal_date_epoch)
        db do
          mailbox = EmailAccount.find(account_id).find_mailbox(mailbox_name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          internal_date = internal_date_epoch && Time.zone.at(internal_date_epoch)
          message = EmailMessage.deliver_raw(mailbox, raw, flags: flags, internal_date: internal_date)
          { uid: message.uid, uid_validity: mailbox.uid_validity }
        end
      end

      def copy(mailbox_id, uids, dest_name)
        db do
          source = Mailbox.find(mailbox_id)
          dest = source.email_account.find_mailbox(dest_name)
          next { error: "no such mailbox", code: :notfound } unless dest

          src_uids = []
          dest_uids = []
          EmailMessage.where(mailbox_id: mailbox_id, uid: uids).order(:uid).each do |m|
            copied = EmailMessage.deliver_raw(dest, m.raw, flags: m.flags, internal_date: m.internal_date)
            src_uids << m.uid
            dest_uids << copied.uid
          end
          { uid_validity: dest.uid_validity, src_uids: src_uids, dest_uids: dest_uids }
        end
      end
    end
  end
end
