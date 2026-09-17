# frozen_string_literal: true

# What an idle connection looked like, for the idle_auto_ban setting: a
# peer that connected and never did any mail work (a banner grab, EHLO and
# gone, a login port nobody logged in on). idle_reason names the shape on
# an individual history row; idle_count is what the ban counts - 1 on an
# idle row, and on a rollup row the idle share of connection_count, so
# collapsed scanner noise still weighs in exactly. Both stay at their
# defaults for every connection that did something.
class AddIdleToClosedConnections < ActiveRecord::Migration[8.1]
  def change
    add_column "mail_on_rails_closed_connections", "idle_count", :integer, null: false, default: 0
    add_column "mail_on_rails_closed_connections", "idle_reason", :string
  end
end
