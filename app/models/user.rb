class User < ApplicationRecord
  has_secure_password
  include GeneratedPassword
  has_many :sessions, dependent: :destroy

  validates :email_address, presence: true, uniqueness: { case_sensitive: false }

  # Live-refresh the users index (subscribed via turbo_stream_from :users).
  after_commit -> { broadcast_refresh_later_to :users }

  normalizes :email_address, with: ->(e) { e.strip.downcase }
end
