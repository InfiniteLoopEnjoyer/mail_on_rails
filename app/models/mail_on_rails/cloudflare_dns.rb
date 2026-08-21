require "cloudflare"

# Adapter over the cloudflare gem (socketry) for DNS record management -
# just what DnsPublisher needs. Token (CLOUDFLARE_API_TOKEN) requires
# Zone:Read (to resolve zone ids by name) + DNS:Edit, scoped to the zones
# we host. Every failure raises CloudflareDns::Error with Cloudflare's
# message; callers surface it to the admin.
#
# Records come back as string-keyed hashes (the raw API shape), not gem
# representations, so callers and test fakes stay decoupled from the gem.
module MailOnRails
  class CloudflareDns
    class Error < StandardError; end

    ENDPOINT = Async::HTTP::Endpoint.parse("https://api.cloudflare.com/client/v4/", timeout: 15)

    def self.enabled?
      ENV["CLOUDFLARE_API_TOKEN"].to_s.strip.present?
    end

    def initialize(token: ENV["CLOUDFLARE_API_TOKEN"].to_s.strip)
      raise Error, "CLOUDFLARE_API_TOKEN is not set" if token.empty?

      @token = token
    end

    def zone_id(name)
      connect do |connection|
        zone = connection.zones.find_by_name(name)
        zone&.result&.fetch(:id) ||
          raise(Error, "no zone named #{name} in this Cloudflare account (is the domain delegated to Cloudflare, and the token scoped to it?)")
      end
    end

    def records(zone_id, type:, name:)
      connect do |connection|
        dns_records(connection, zone_id).each(type: type, name: name)
                                        .map { |record| record.result.deep_stringify_keys }
      end
    end

    def create_record(zone_id, attrs)
      attrs = attrs.symbolize_keys
      connect do |connection|
        dns_records(connection, zone_id)
          .create(attrs.fetch(:type), attrs.fetch(:name), attrs.fetch(:content), **attrs.except(:type, :name, :content))
          .result.deep_stringify_keys
      end
    end

    def update_record(zone_id, record_id, attrs)
      connect do |connection|
        record = dns_records(connection, zone_id).find_by_id(record_id)
        # Record.put rather than record.update_content: the latter reads
        # type/name off the representation, forcing an extra GET first.
        Cloudflare::DNS::Record.put(record.resource, attrs.symbolize_keys)
                               .result.deep_stringify_keys
      end
    end

    private

    def dns_records(connection, zone_id)
      connection.zones.find_by_id(zone_id).dns_records
    end

    # Opens a connection, runs the block inside the gem's Sync reactor and
    # closes the connection; collapses every failure mode into our Error.
    def connect(&block)
      Cloudflare.connect(ENDPOINT, token: @token, &block)
    rescue Cloudflare::RequestError => e
      raise Error, Cloudflare::RequestError.error_string_for(e.value)
    rescue Async::TimeoutError, Timeout::Error, SystemCallError, IOError, SocketError, OpenSSL::SSL::SSLError => e
      raise Error, "#{e.class}: #{e.message}"
    end
  end
end
