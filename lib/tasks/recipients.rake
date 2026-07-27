# Manage the RCPT-time recipient list shared with the exim edge.
#
#   bin/rails mail_on_rails:recipients:sync   # rewrite the exim local_recipients file from the DB
namespace :mail_on_rails do
  namespace :recipients do
    desc "Rewrite the exim local_recipients file from the EmailAccount table"
    task sync: :environment do
      puts "exim sync: #{EximLocalRecipients.sync!}"
      puts EximLocalRecipients.current.map { |address| "  #{address}" }
    end
  end
end
