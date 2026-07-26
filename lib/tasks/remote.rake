# Pull production state down to this development machine.
#
#   bin/rails mail_on_rails:remote:db     # dump the prod primary DB (compressed), import into the dev DB,
#                                         # then ask whether to keep the dump file (KEEP=1/0 skips the prompt)
#
# DKIM keys ride along: they live encrypted in the domains table, and this
# machine holds the same config/master.key, so the imported rows decrypt.
#
# The remote host comes from config/deploy.prod.yml (servers.web.hosts[0]);
# override with REMOTE_HOST=... . The dump travels compressed (pg_dump -Fc,
# custom format) and is restored with --no-owner --no-privileges, so the
# production role (mail_on_rails) never needs to exist locally - restored
# objects belong to the local dev user. Only the PRIMARY database is pulled;
# cache/queue/cable are operational state with no dev value. Active Storage
# blobs on the prod volume are not synced (message bodies live in the
# email_messages.raw column, so mail content comes along regardless).

namespace :remote do
  require "rainbow"

  module RemotePull
    module_function

    DB_CONTAINER = "mail_on_rails-db"

    def host
      ENV["REMOTE_HOST"].presence || begin
        config = YAML.load_file(Rails.root.join("config/deploy.prod.yml"))
        config.dig("servers", "web", "hosts", 0)
      rescue Errno::ENOENT
        nil
      end || abort(Rainbow("Set REMOTE_HOST=... (no config/deploy.prod.yml found)").red)
    end

    def remote_db_user = ENV.fetch("REMOTE_DB_USER", "mail_on_rails")
    def remote_db_name = ENV.fetch("REMOTE_DB_NAME", "mail_on_rails_production")

    def dev_db_name
      ActiveRecord::Base.configurations.configs_for(env_name: "development", name: "primary").database
    end

    def ask?(question)
      print Rainbow("#{question} [y/N] ").cyan
      $stdout.flush
      $stdin.gets.to_s.strip.casecmp?("y")
    end

    def step(text) = puts(Rainbow("==> #{text}").cyan)
    def ok(text)   = puts(Rainbow(text).green)
    def warn(text) = puts(Rainbow(text).yellow)
  end

  desc "Dump the production primary DB and import it into the development DB"
  task db: :environment do
    abort Rainbow("refusing: this task rebuilds the DEVELOPMENT database").red unless Rails.env.development?

    host = RemotePull.host

    dump = Rails.root.join("#{RemotePull.remote_db_name}_#{Time.now.strftime("%Y%m%d_%H%M%S")}.dump")

    RemotePull.step "Dumping #{RemotePull.remote_db_name} from #{host} (pg_dump -Fc, compressed)..."
    dumped = system("ssh root@#{host} 'docker exec #{RemotePull::DB_CONTAINER} " \
                    "pg_dump -Fc -U #{RemotePull.remote_db_user} #{RemotePull.remote_db_name}' > #{dump}")
    abort Rainbow("dump failed").red unless dumped && File.size?(dump)
    RemotePull.ok "  #{dump.basename} (#{(File.size(dump) / 1024.0 / 1024.0).round(1)} MB)"

    RemotePull.step "Restoring into #{RemotePull.dev_db_name} (--clean --no-owner --no-privileges)..."
    # Drop our own connections so --clean can drop objects under us.
    ActiveRecord::Base.connection_handler.clear_all_connections!
    restored = system("pg_restore --clean --if-exists --no-owner --no-privileges " \
                      "-d #{RemotePull.dev_db_name} #{dump}")
    unless restored
      # pg_restore exits non-zero for ignorable ownership/extension
      # errors too; the row counts below are the real health check.
      RemotePull.warn "  pg_restore reported errors (often harmless COMMENT/EXTENSION ownership noise; " \
                      "if the restore truly failed, stop bin/dev and re-run)"
    end

    # The dump carries ar_internal_metadata saying "production", which
    # makes every local db task refuse to run. Stamp it back.
    ActiveRecord::Base.connection.execute("UPDATE ar_internal_metadata SET value = 'development' WHERE key = 'environment'")

    RemotePull.step "Imported:"
    { "accounts" => EmailAccount, "domains" => Domain, "messages" => EmailMessage,
      "dmarc report rows" => DmarcReport, "users" => User }.each do |label, model|
      RemotePull.ok "  #{model.count} #{label}"
    end

    keep = ENV["KEEP"].present? ? ENV["KEEP"].match?(/\A(1|true|y)/i) : RemotePull.ask?("Keep the dump file at #{dump}?")
    if keep
      RemotePull.ok "Kept #{dump}"
    else
      File.delete(dump)
      RemotePull.ok "Deleted #{dump}"
    end
  end
end
