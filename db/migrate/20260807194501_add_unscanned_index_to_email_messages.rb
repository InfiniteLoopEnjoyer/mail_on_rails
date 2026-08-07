class AddUnscannedIndexToEmailMessages < ActiveRecord::Migration[8.0]
  # RescanUnscannedMessagesJob polls for scan_status = 'unscanned' hourly;
  # the partial index keeps that a lookup instead of a sequential scan
  # over the biggest table, and costs nearly nothing since the unscanned
  # set is empty whenever clamd is healthy.
  def change
    add_index :email_messages, :scan_status, where: "scan_status = 'unscanned'",
              name: "index_email_messages_on_unscanned"
  end
end
