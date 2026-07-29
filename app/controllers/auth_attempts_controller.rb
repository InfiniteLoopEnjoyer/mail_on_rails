# Read-only view of failed credential checks across IMAP, SMTP AUTH and
# the web login (AuthAttempt). Nothing here enforces anything - blocking is
# AuthThrottle's job - this is for looking at what has been arriving and
# deciding whether a range is worth blocking at the firewall.
class AuthAttemptsController < ApplicationController
  WINDOWS = { "24h" => 1.day, "7d" => 7.days, "30d" => 30.days }.freeze
  DEFAULT_WINDOW = "7d"

  def index
    @window = WINDOWS.key?(params[:window]) ? params[:window] : DEFAULT_WINDOW
    since = WINDOWS.fetch(@window).ago

    @totals = AuthAttempt.totals(since: since)
    @targeted = AuthAttempt.targeted_accounts(since: since)
    @ranges = AuthAttempt.top_ranges(since: since)
    @usernames = AuthAttempt.top_usernames(since: since)
    @recent_real = AuthAttempt.against_real_accounts.recent(since)
                              .order(occurred_at: :desc).limit(25)
  end
end
