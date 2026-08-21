# frozen_string_literal: true

# The RateLimiter's tarpit verdict on the connection log (2026-08): how many
# seconds the connection was made to wait before its banner, nil for the
# overwhelming majority that weren't slowed. Lets the ops UI show which
# connections the rate limiter actually touched instead of the state living
# only in the listener's memory.
class AddTarpitSecondsToClosedConnections < ActiveRecord::Migration[8.1]
  def change
    add_column "mail_on_rails_closed_connections", "tarpit_seconds", :float
  end
end
