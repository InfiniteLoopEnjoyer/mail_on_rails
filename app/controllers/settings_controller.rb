# Operational internals with no other natural home in the UI. Today that
# is the two files this app maintains for the exim edge on the shared
# mailconf volume (hosted domains + local recipients), shown verbatim with
# a live comparison against the database tables they mirror - the point is
# seeing exactly what exim is acting on right now, drift included.
class SettingsController < ApplicationController
  # One exim-owned file: what's on disk (lines/mtime via the model that
  # writes it) next to what the DB says should be there. missing = rows
  # exim doesn't know yet; stale = file entries with no DB row behind them.
  EximFile = Struct.new(:key, :label, :env_var, :writer, :db, :description, keyword_init: true) do
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
    @exim_files = exim_files
  end

  # Rewrite one of the files from the database on demand - the button-shaped
  # version of the mail_on_rails:{domains,recipients}:sync rake tasks, for
  # when the page shows drift. Never forces an empty domain list; that stays
  # a deliberate FORCE_EMPTY=1 rake invocation.
  def sync
    file = exim_files.find { |f| f.key == params[:file] }
    raise ActionController::RoutingError, "unknown exim file #{params[:file].inspect}" unless file

    begin
      case file.writer.sync!
      when :written then flash[:notice] = "#{file.label} file rewritten from the database."
      when :skipped then flash[:alert] = "#{file.label}: #{file.env_var} is not set, nothing was written."
      end
    rescue EximLocalDomains::Error, EximLocalRecipients::Error => e
      flash[:alert] = "#{file.label} sync failed: #{e.message}"
    end
    redirect_to settings_path
  end

  private

  def exim_files
    [
      EximFile.new(
        key: "domains",
        label: "Hosted domains", env_var: "MAIL_ON_RAILS_EXIM_DOMAINS_FILE",
        writer: EximLocalDomains, db: Domain.order(:name).pluck(:name),
        description: "Domains exim accepts mail for (its local_domains list). " \
                     "Rewritten on domain add/remove; a recipient outside these " \
                     "domains is refused as relaying."
      ),
      EximFile.new(
        key: "recipients",
        label: "Local recipients", env_var: "MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE",
        writer: EximLocalRecipients, db: EximLocalRecipients.addresses,
        description: "Addresses exim accepts at RCPT time (its local_recipients " \
                     "list): accounts and aliases. Rewritten on account or alias " \
                     "add/remove/rename; an address in a hosted domain but not " \
                     "in this file gets 550 no such user."
      )
    ]
  end
end
