# View of failed credential checks across IMAP, SMTP AUTH and the web
# login (AuthAttempt), plus the ban buttons that act on them (BannedIp -
# automatic short blocks stay AuthThrottle's job). range drills into one
# /24's individual addresses so a single machine can be banned without
# taking the whole range.
class AuthAttemptsController < ApplicationController
  include BanCoverage

  WINDOWS = { "24h" => 1.day, "7d" => 7.days, "30d" => 30.days }.freeze
  DEFAULT_WINDOW = "7d"

  before_action :set_window

  def index
    @totals = AuthAttempt.totals(since: @since)
    @targeted = AuthAttempt.targeted_accounts(since: @since)
    @ranges = AuthAttempt.top_ranges(since: @since)
    @usernames = AuthAttempt.top_usernames(since: @since)
    @recent_real = AuthAttempt.against_real_accounts.recent(@since)
                              .order(occurred_at: :desc).limit(25)
    load_bans
  end

  def range
    @range = params[:cidr].to_s
    begin
      IPAddr.new(@range)
    rescue IPAddr::Error
      return redirect_to auth_attempts_path(window: @window),
                         alert: "#{@range.inspect} is not an IP range."
    end

    @ips = AuthAttempt.range_detail(@range, since: @since)
    load_bans
  end

  private

  def set_window
    @window = WINDOWS.key?(params[:window]) ? params[:window] : DEFAULT_WINDOW
    @since = WINDOWS.fetch(@window).ago
  end

  def load_bans
    @bans = BannedIp.order(created_at: :desc).to_a
    @manual_bans = @bans.select { |ban| ban.source == "manual" }
    @drop_bans = @bans.count { |ban| ban.source == "spamhaus_drop" }
    @drop_refreshed_at = @bans.filter_map { |ban| ban.updated_at if ban.source == "spamhaus_drop" }.max
  end
end
