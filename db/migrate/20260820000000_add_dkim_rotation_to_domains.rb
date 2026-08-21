# frozen_string_literal: true

# DKIM key rotation state on Domain. dkim_selector overrides the global
# static setting once a rotation has happened; the next_* pair holds a
# staged key waiting for its DNS TXT to become visible, and the retired_*
# pair remembers the previous selector until its record is revoked
# (empty p=) after the grace window. See Domain#stage_dkim_rotation! and
# RotateDkimKeysJob.
class AddDkimRotationToDomains < ActiveRecord::Migration[8.1]
  def change
    change_table "mail_on_rails_domains", bulk: true do |t|
      t.string :dkim_selector
      t.string :dkim_next_selector
      t.text :dkim_next_private_key
      t.string :dkim_retired_selector
      t.datetime :dkim_retired_at
      t.datetime :dkim_rotated_at
    end
  end
end
