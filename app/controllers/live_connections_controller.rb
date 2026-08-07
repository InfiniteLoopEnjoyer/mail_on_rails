# Live view of the in-process mail servers' connections - the SMTP and
# IMAP sidebar sections, one subclass per protocol. The servers run as
# threads inside this very Puma process (the :mail_on_rails plugin), so
# the page snapshots Server#connections with a method call, no transport;
# a poll Stimulus controller reloads the page's turbo frame every few
# seconds to keep it live. Ban buttons reuse BannedIp - banning also
# drops the address's live connections (BannedIpsController).
class LiveConnectionsController < ApplicationController
  include BanCoverage

  # Window tabs for the history section (ClosedConnection); the live
  # table above it always shows the present moment regardless.
  WINDOWS = { "24h" => 1.day, "7d" => 7.days, "30d" => 30.days }.freeze
  DEFAULT_WINDOW = "24h"

  def show
    require "mail_on_rails/boot"
    @window = WINDOWS.key?(params[:window]) ? params[:window] : DEFAULT_WINDOW
    @since = WINDOWS.fetch(@window).ago
    @server = MailOnRails::Boot.server(protocol)
    @connections = (@server&.connections || []).sort_by { |conn| conn[:connected_at] }
    # History is DB-backed, so it renders even when no server runs in
    # this process.
    @history = ClosedConnection.recent_list(protocol, since: @since)
    @bans = BannedIp.order(created_at: :desc).to_a
  end

  private

  # :smtp / :imap, from the subclass naming (SmtpController -> "smtp").
  def protocol
    controller_name.to_sym
  end
end
