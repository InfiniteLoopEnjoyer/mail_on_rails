class Session < ApplicationRecord
  belongs_to :user

  # Activity is only written when it's stale by this much - one indexed
  # UPDATE per interval per session, not one per request.
  TOUCH_INTERVAL = 5.minutes

  before_create { self.last_active_at ||= Time.current }

  scope :active, -> { where(last_active_at: idle_timeout.ago..) }

  # Server-side idle timeout, the authoritative one (the cookie horizon
  # below only bounds how long the browser keeps presenting the id).
  def self.idle_timeout = Integer(ENV.fetch("MAIL_ON_RAILS_SESSION_IDLE_TIMEOUT", 86_400)).seconds

  # Cookie expiry; re-set on activity, so it slides.
  def self.cookie_lifetime = Integer(ENV.fetch("MAIL_ON_RAILS_SESSION_COOKIE_LIFETIME", 14 * 86_400)).seconds

  # Expired sessions are refused at resume; this removes the rows.
  def self.prune!(now: Time.current) = where(last_active_at: ...(now - idle_timeout)).delete_all

  def expired? = last_active_at < self.class.idle_timeout.ago

  def touch_activity! = update_column(:last_active_at, Time.current)
end
