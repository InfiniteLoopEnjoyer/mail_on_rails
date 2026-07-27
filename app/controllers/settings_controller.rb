# Operational internals with no other natural home in the UI. Today that
# is the two files this app maintains for the exim edge on the shared
# mailconf volume (hosted domains + local recipients), shown verbatim with
# a live comparison against the database tables they mirror - the point is
# seeing exactly what exim is acting on right now, drift included.
class SettingsController < ApplicationController
  # One exim-owned file: what's on disk (lines/mtime via the model that
  # writes it) next to what the DB says should be there. missing = rows
  # exim doesn't know yet; stale = file entries with no DB row behind them.
  EximFile = Struct.new(:label, :env_var, :writer, :db, :description, keyword_init: true) do
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
    @exim_files = [
      EximFile.new(
        label: "Hosted domains", env_var: "MAIL_ON_RAILS_EXIM_DOMAINS_FILE",
        writer: EximLocalDomains, db: Domain.order(:name).pluck(:name),
        description: "Domains exim accepts mail for (its local_domains list). " \
                     "Rewritten on domain add/remove; a recipient outside these " \
                     "domains is refused as relaying."
      ),
      EximFile.new(
        label: "Local recipients", env_var: "MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE",
        writer: EximLocalRecipients, db: EmailAccount.order(:email).pluck(:email),
        description: "Addresses exim accepts at RCPT time (its local_recipients " \
                     "list). Rewritten on account add/remove/rename; an address " \
                     "in a hosted domain but not in this file gets 550 no such user."
      )
    ]
  end
end
