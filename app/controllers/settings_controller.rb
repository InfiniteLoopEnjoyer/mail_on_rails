# Operational internals with no other natural home in the UI: app-wide
# knobs (Setting) and the banned_ips file this app maintains for its
# in-process mail listeners, shown verbatim with a live comparison against
# the database rows it mirrors - the point is seeing exactly what the
# listeners are acting on right now, drift included.
class SettingsController < ApplicationController
  # One app-maintained file: what's on disk (lines/mtime via the model
  # that writes it) next to what the DB says should be there. missing =
  # rows the file doesn't have yet; stale = file entries with no DB row
  # behind them.
  SyncedFile = Struct.new(:key, :label, :env_var, :writer, :db, :description, keyword_init: true) do
    def path = ENV[env_var]
    def configured? = path.present?
    def exists? = configured? && File.exist?(path)
    def lines = writer.current
    def mtime = (File.mtime(path) if exists?)
    def missing = db - lines
    def stale = lines - db
    def in_sync? = exists? && missing.empty? && stale.empty?
  end

  def show
    @synced_files = synced_files
    @trash_retention_days = Setting.trash_retention_days
  end

  # The page's one writable knob so far: how many days mail sits in Trash
  # before PurgeTrashJob deletes it permanently.
  def update
    Setting.trash_retention_days = params[:trash_retention_days]
    redirect_to settings_path, notice: "Trash retention set to #{Setting.trash_retention_days} days."
  rescue ArgumentError, TypeError
    redirect_to settings_path, alert: "Trash retention must be a whole number of days, at least 1."
  end

  # Rewrite one of the files from the database on demand - the
  # button-shaped version of the mail_on_rails:banned_ips:sync rake task,
  # for when the page shows drift.
  def sync
    file = synced_files.find { |f| f.key == params[:file] }
    raise ActionController::RoutingError, "unknown synced file #{params[:file].inspect}" unless file

    begin
      case file.writer.sync!
      when :written then flash[:notice] = "#{file.label} file rewritten from the database."
      when :skipped then flash[:alert] = "#{file.label}: #{file.env_var} is not set, nothing was written."
      end
    rescue BannedIpsFile::Error => e
      flash[:alert] = "#{file.label} sync failed: #{e.message}"
    end
    redirect_to settings_path
  end

  private

  def synced_files
    [
      SyncedFile.new(
        key: "banned_ips",
        label: "Banned IPs", env_var: "MAIL_ON_RAILS_BANNED_IPS_FILE",
        writer: BannedIpsFile, db: BannedIpsFile.cidrs,
        description: "IPs and ranges banned from the auth attempts page (plus " \
                     "the imported Spamhaus DROP list). Read by the in-process " \
                     "SMTP and IMAP listeners, which drop matches before any " \
                     "banner, and checked at web login. Rewritten on ban/unban."
      )
    ]
  end
end
