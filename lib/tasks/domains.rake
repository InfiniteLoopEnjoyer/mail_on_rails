# Manage the hosted-domain list shared with the exim edge.
#
#   bin/rails mail_on_rails:domains:bootstrap                 # Domain rows from existing accounts (+ DOMAINS="a.com b.com"), then sync
#   bin/rails mail_on_rails:domains:sync                      # rewrite the exim local_domains file from the DB
#   bin/rails mail_on_rails:domains:sync FORCE_EMPTY=1        # allow writing an empty list (550s all inbound!)
namespace :mail_on_rails do
  namespace :domains do
    desc "Create Domain rows for existing accounts' domains and sync exim"
    task bootstrap: :environment do
      names = EmailAccount.pluck(:email).map { |email| email.split("@").last.to_s.downcase }.uniq
      names |= ENV["DOMAINS"].to_s.split.map(&:downcase)

      names.sort.each do |name|
        domain = Domain.find_or_create_by!(name: name)
        domain.ensure_dmarc_account!
        puts "#{domain.name}: #{domain.previously_new_record? ? "created" : "exists"}, " \
             "DKIM key #{domain.dkim_private_key.present? ? "present" : "missing"}, " \
             "reports account #{domain.dmarc_address}"
      end
      puts "exim sync: #{EximLocalDomains.sync!(force_empty: names.empty?)}"
    end

    desc "Rewrite the exim local_domains file from the Domain table"
    task sync: :environment do
      puts "exim sync: #{EximLocalDomains.sync!(force_empty: ENV["FORCE_EMPTY"].present?)}"
      puts EximLocalDomains.current.map { |name| "  #{name}" }
    end
  end
end
