# QRESYNC (RFC 7162) expunge tombstone: which uid vanished from which
# mailbox at which mod-sequence, so a reconnecting IMAP client can be told
# "VANISHED (EARLIER) <uids>" instead of re-syncing the whole mailbox.
# History is bounded per mailbox; pruning raises the mailbox's
# tombstone_floor, past which answers fall back to the (correct but
# larger) set of every uid ever allocated and no longer present.
module MailOnRails
  class ExpungedMessage < Record
    belongs_to :mailbox

    TOMBSTONE_LIMIT = 1000

    def self.record!(mailbox, uid, modseq, limit: TOMBSTONE_LIMIT)
      create!(mailbox: mailbox, uid: uid, modseq: modseq)
      prune!(mailbox, limit: limit)
    end

    def self.prune!(mailbox, limit: TOMBSTONE_LIMIT)
      scope = where(mailbox_id: mailbox.id)
      overflow = scope.count - limit
      return unless overflow.positive?

      doomed_ids = scope.order(:modseq, :id).limit(overflow).pluck(:id, :modseq)
      floor = doomed_ids.map(&:last).max
      where(id: doomed_ids.map(&:first)).delete_all
      mailbox.update_columns(tombstone_floor: [ mailbox.tombstone_floor, floor ].max)
    end
  end
end
