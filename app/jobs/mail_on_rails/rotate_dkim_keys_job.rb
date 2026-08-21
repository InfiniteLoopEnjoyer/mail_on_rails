require "mail_on_rails/settings"

# Drives the DKIM rotation lifecycle for every hosted domain, daily from
# config/recurring.yml (see Domain's rotation section for the state
# machine):
#
#   promote  a staged key whose TXT is now visible in public DNS becomes
#            the signing key; the old selector is remembered as retired
#   stage    a key past dkim_rotation_days is due: mint the next key and
#            publish its TXT via Cloudflare (auto-staging is skipped when
#            Cloudflare isn't configured - stage manually and publish the
#            TXT yourself, the job still promotes it once visible)
#   revoke   a retired selector past the grace window gets its TXT
#            replaced with an empty p= (RFC 6376 key revocation - old
#            signatures stop verifying, killing replays), then the
#            retired state clears
#
# Promotion runs before staging so a key staged this run never promotes
# in the same run - its TXT cannot be visible yet. Everything is
# per-domain fail-soft: one domain's DNS trouble must not stall the rest.
module MailOnRails
  class RotateDkimKeysJob < BaseJob
    queue_as :default

    def perform(resolver: DnsCheck::Resolver.new, client: nil)
      Domain.find_each do |domain|
        next if domain.dkim_private_key.blank?

        promote(domain, resolver)
        stage(domain, client)
        revoke(domain, client)
      rescue StandardError => e
        Rails.logger.error "[mail_on_rails] DKIM rotation for #{domain.name} failed: #{e.class}: #{e.message}"
      end
    end

    private

    def rotation_days
      MailOnRails::Settings[:dkim_rotation_days].to_i
    end

    def promote(domain, resolver)
      return unless domain.dkim_staged?

      records = resolver.txt(domain.dkim_next_txt_name)
      return if records.nil? # DNS unreachable - try again tomorrow

      expected = dkim_p(domain.dkim_next_txt_value)
      return unless records.any? { |r| dkim_p(r) == expected }

      domain.promote_dkim_rotation!
      Rails.logger.info "[mail_on_rails] DKIM key for #{domain.name} promoted to selector " \
                        "#{domain.dkim_selector} (retiring #{domain.dkim_retired_selector})"
    end

    def stage(domain, client)
      return unless domain.dkim_rotation_due?(rotation_days)
      # Auto-staging publishes the new TXT itself; without Cloudflare that
      # would strand a staged key nobody publishes.
      return unless CloudflareDns.enabled?

      domain.stage_dkim_rotation!
      client ||= CloudflareDns.new
      zone = client.zone_id(domain.name)
      if client.records(zone, type: "TXT", name: domain.dkim_next_txt_name).empty?
        client.create_record(zone, type: "TXT", name: domain.dkim_next_txt_name,
                             content: DnsPublisher.quoted_txt(domain.dkim_next_txt_value), ttl: DnsPublisher::TTL)
      end
      Rails.logger.info "[mail_on_rails] DKIM rotation staged for #{domain.name}: published " \
                        "#{domain.dkim_next_txt_name}, promoting once public DNS shows it"
    end

    def revoke(domain, client)
      return if domain.dkim_retired_selector.blank?
      return unless domain.dkim_retired_at && domain.dkim_retired_at <= Domain::DKIM_RETIRE_GRACE.ago

      if CloudflareDns.enabled?
        client ||= CloudflareDns.new
        zone = client.zone_id(domain.name)
        if (record = client.records(zone, type: "TXT", name: domain.dkim_retired_txt_name).first)
          client.update_record(zone, record["id"], type: "TXT", name: domain.dkim_retired_txt_name,
                               content: DnsPublisher.quoted_txt("v=DKIM1; p="), ttl: DnsPublisher::TTL)
        end
        Rails.logger.info "[mail_on_rails] retired DKIM selector #{domain.dkim_retired_selector} for " \
                          "#{domain.name} revoked (empty p=)"
      else
        Rails.logger.warn "[mail_on_rails] retired DKIM selector #{domain.dkim_retired_selector} for " \
                          "#{domain.name} passed its grace window - revoke #{domain.dkim_retired_txt_name} " \
                          "manually (publish \"v=DKIM1; p=\")"
      end
      domain.clear_retired_dkim!
    end

    def dkim_p(content)
      content.to_s.gsub(/[\s"]/, "")[%r{p=([A-Za-z0-9+/=]*)}, 1]
    end
  end
end
