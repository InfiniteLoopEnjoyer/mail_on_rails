# Manage the hosted-domain list.
#
#   bin/rails mail_on_rails:domains:bootstrap   # Domain rows from existing accounts (+ DOMAINS="a.com b.com")
namespace :mail_on_rails do
  namespace :domains do
    desc "Create Domain rows for existing accounts' domains"
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
    end
  end
end
