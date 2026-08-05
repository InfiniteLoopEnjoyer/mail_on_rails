# Manage the banned-IPs file shared with the exim and IMAP edges.
#
#   bin/rails mail_on_rails:banned_ips:sync   # rewrite the shared banned_ips file from the DB
namespace :mail_on_rails do
  namespace :banned_ips do
    desc "Rewrite the shared banned_ips file from the BannedIp table"
    task sync: :environment do
      puts "banned_ips sync: #{BannedIpsFile.sync!}"
      puts BannedIpsFile.current.map { |cidr| "  #{cidr}" }
    end
  end
end
