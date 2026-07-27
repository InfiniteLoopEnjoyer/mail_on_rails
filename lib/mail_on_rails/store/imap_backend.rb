# frozen_string_literal: true

require "mail_on_rails/clamav_scanner"

module MailOnRails
  module Store
    # The app-side implementation of the IMAP store contract: everything
    # the IMAP server is allowed to do, on Active Record. The daemon never
    # loads this - it talks to MailOnRails::InternalController, which
    # delegates here (see docs/store_contract.md and Store::Imap, the HTTP
    # client the daemon actually uses).
    class ImapBackend < Base
      # Quarantine is kept out of LIST so mail clients don't sync a folder
      # of flagged malware; it stays SELECTable by name on purpose (review
      # happens in the web UI, but a power user can still get at it).
      def list_mailboxes(account_id)
        db do
          account = EmailAccount.find(account_id)
          { mailboxes: account.mailboxes.where.not(name: Mailbox::QUARANTINE).order(:name).pluck(:name) }
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

      def delete_mailbox(account_id, name)
        db do
          mailbox = EmailAccount.find(account_id).find_mailbox(name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          mailbox.destroy!
          {}
        end
      end

      # Renames the mailbox and everything under it in the "/" hierarchy.
      def rename_mailbox(account_id, from, to)
        db do
          account = EmailAccount.find(account_id)
          mailbox = account.find_mailbox(from)
          next { error: "no such mailbox", code: :notfound } unless mailbox
          next { error: "mailbox exists", code: :exists } if account.find_mailbox(to)

          Mailbox.transaction do
            prefix = "#{mailbox.name}/"
            escaped = prefix.gsub(/[\\%_]/) { |c| "\\#{c}" }
            account.mailboxes.where("name LIKE ?", "#{escaped}%").find_each do |child|
              child.update!(name: to + child.name[mailbox.name.length..])
            end
            mailbox.update!(name: to)
          end
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

      # uids: nil removes every \Deleted message; a list restricts removal
      # to \Deleted messages with those UIDs (UID EXPUNGE).
      def expunge(mailbox_id, uids = nil)
        db do
          deleted = EmailMessage.where(mailbox_id: mailbox_id)
                                .where("flags LIKE ?", "%\\\\Deleted%")
                                .order(:uid)
          deleted = deleted.where(uid: uids) if uids
          removed = deleted.map(&:uid)
          deleted.destroy_all
          { uids: removed }
        end
      end

      # APPEND is an authenticated write path with no scan in front of it
      # (unlike inbound mail, which the mailroom scans), so it scans here
      # (on by default; SMTP_CLAMAV_ADDR="" disables). Infected uploads are
      # refused - the
      # IMAP server renders the envelope as "NO APPEND failed: ...". A scanner outage stores the message in place flagged
      # "unscanned" rather than refusing or quarantining: this is an
      # authenticated user writing their own Sent/Drafts copies, and hiding
      # those on clamd downtime would break every mail client.
      def append(account_id, mailbox_name, raw, flags, internal_date_epoch)
        db do
          mailbox = EmailAccount.find(account_id).find_mailbox(mailbox_name)
          next { error: "no such mailbox", code: :notfound } unless mailbox

          scan_status = nil
          virus_name = nil
          if MailOnRails::ClamavScanner.enabled?
            result = MailOnRails::ClamavScanner.scan(raw)
            if result.infected?
              log(:warn, "IMAP APPEND refused for account #{account_id}: virus #{result.virus}")
              next { error: "message rejected: virus detected (#{result.virus})", code: :infected }
            end
            scan_status = result.clean? ? "clean" : "unscanned"
          end

          internal_date = internal_date_epoch && Time.zone.at(internal_date_epoch)
          message = EmailMessage.deliver_raw(mailbox, raw, flags: flags, internal_date: internal_date,
                                             scan_status: scan_status)
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
            # Same bytes, same verdict - no rescan on copy.
            copied = EmailMessage.deliver_raw(dest, m.raw, flags: m.flags, internal_date: m.internal_date,
                                              scan_status: m.scan_status, virus_name: m.virus_name)
            src_uids << m.uid
            dest_uids << copied.uid
          end
          { uid_validity: dest.uid_validity, src_uids: src_uids, dest_uids: dest_uids }
        end
      end

      # RFC 6851 MOVE as one transaction: copy into the destination and
      # remove the source rows together, so a failure leaves the message
      # in exactly one mailbox.
      def move(mailbox_id, uids, dest_name)
        db do
          source = Mailbox.find(mailbox_id)
          dest = source.email_account.find_mailbox(dest_name)
          next { error: "no such mailbox", code: :notfound } unless dest

          src_uids = []
          dest_uids = []
          EmailMessage.transaction do
            EmailMessage.where(mailbox_id: mailbox_id, uid: uids).order(:uid).each do |m|
              # Same bytes, same verdict - no rescan on move.
              copied = EmailMessage.deliver_raw(dest, m.raw, flags: m.flags, internal_date: m.internal_date,
                                                scan_status: m.scan_status, virus_name: m.virus_name)
              src_uids << m.uid
              dest_uids << copied.uid
              m.destroy!
            end
          end
          { uid_validity: dest.uid_validity, src_uids: src_uids, dest_uids: dest_uids }
        end
      end
    end
  end
end
