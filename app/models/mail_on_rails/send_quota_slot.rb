# The durable half of MailOnRails::SendQuota: recipients an authenticated
# account has consumed, counted in the database so the budget is one
# budget. Production runs the web process (composer, vacation replies,
# Solid Queue) and the SMTP listener (authenticated submission) in
# separate containers; an in-memory counter in each hands a stolen
# mailbox password the configured limit per container, and a restart
# resets it. Same reasoning that moved the auth throttle into
# AuthThrottle rows.
#
# The sliding window is stored as fixed BUCKET_SECONDS buckets: one row
# per (account, bucket start). A consumer locks every live bucket row of
# the account (oldest first) before it sums them and increments its own,
# so the "sum the live window, then increment" step is serialized without
# a table lock - including across a bucket boundary, where two consumers
# hold different current buckets: each has inserted its own row before it
# locks, so their lock sets always share at least one row and one of them
# waits. The window sum takes the whole bucket straddling the window's
# start, so the cap errs conservative by up to one bucket rather than
# lenient.
#
# Rows older than the window are pruned per account on every consume (a
# quiet account leaves at most window/BUCKET_SECONDS rows behind);
# prune! is the scheduled sweep for the rest.
module MailOnRails
  class SendQuotaSlot < Record
    BUCKET_SECONDS = 60

    class << self
      # Consumes one slot for +account+ if fewer than +limit+ were consumed
      # in the last +window+ seconds; true when consumed, false when the
      # budget is exhausted (nothing is written in that case).
      def consume(account, limit:, window:, now: Time.current)
        key = normalize(account)
        bucket = bucket_start(now)
        row = find_or_create_by!(account_key: key, window_start: bucket) { |r| r.used = 0 }
        consumed = false
        transaction do
          # SELECT ... FOR UPDATE over the whole live window, in a fixed
          # order so two consumers can never deadlock, on PostgreSQL/MySQL;
          # SQLite ignores the FOR UPDATE but its IMMEDIATE write
          # transactions serialize this section anyway. The sum is taken
          # from the locked rows themselves, never from a second query.
          rows = live(key, window, now).lock.order(:window_start, :id).to_a
          raise ActiveRecord::RecordNotFound unless rows.any? { |r| r.id == row.id }

          if rows.sum { |r| r.used.to_i } < limit
            row.increment!(:used)
            consumed = true
          end
        end
        stale(key, window, now).delete_all
        consumed
      rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordNotFound
        # Another process created the bucket row between our read and
        # insert, or pruned it between our find and our lock.
        retry
      end

      # Slots consumed by +account+ inside the window (for the UI and
      # tests; consume itself sums the rows it locked).
      def used(account, window:, now: Time.current)
        live(normalize(account), window, now).sum(:used)
      end

      # Drops every bucket older than +window+ seconds, any account.
      def prune!(window: MailOnRails::Settings[:smtp_send_quota_window], now: Time.current)
        where(window_start: ...(now - window - BUCKET_SECONDS)).delete_all
      end

      def normalize(account) = account.to_s.strip.downcase

      # UTC rather than Time.zone: consume runs on listener threads, where
      # a thread-local zone may be unset.
      def bucket_start(now)
        Time.at((now.to_i / BUCKET_SECONDS) * BUCKET_SECONDS).utc
      end

      private

      # Buckets that overlap the window at all - conservative at the edge.
      def live(key, window, now)
        where(account_key: key).where(window_start: (now - window - BUCKET_SECONDS)..)
      end

      def stale(key, window, now)
        where(account_key: key).where(window_start: ...(now - window - BUCKET_SECONDS))
      end
    end
  end
end
