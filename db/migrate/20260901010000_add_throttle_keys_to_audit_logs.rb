# frozen_string_literal: true

# The audit logs' per-source write caps (AuthAttempt / ClosedConnection
# rollups) count per Netserv.throttle_key - the address for IPv4, the /64
# for IPv6 - so an IPv6 scanner cannot dodge the cap with a fresh /128
# per attempt. Rows keep the full address in ip; the key gets its own
# indexed column because a /64 has no stable string prefix once the
# address is compressed. Existing rows stay NULL and age out of the
# window on their own.
class AddThrottleKeysToAuditLogs < ActiveRecord::Migration[8.1]
  def change
    add_column "mail_on_rails_auth_attempts", "throttle_key", :string
    add_index "mail_on_rails_auth_attempts", %w[throttle_key occurred_at],
              name: "index_auth_attempts_on_throttle_key_and_occurred_at"

    add_column "mail_on_rails_closed_connections", "throttle_key", :string
    add_index "mail_on_rails_closed_connections", %w[protocol throttle_key closed_at],
              name: "index_closed_connections_on_protocol_throttle_key_closed_at"
  end
end
