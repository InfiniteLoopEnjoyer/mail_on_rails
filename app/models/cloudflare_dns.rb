require "net/http"
require "json"

# Thin Cloudflare API v4 client for DNS record management - just what
# DnsPublisher needs. Token (CLOUDFLARE_API_TOKEN) requires Zone:Read (to
# resolve zone ids by name) + DNS:Edit, scoped to the zones we host.
# Every failure raises CloudflareDns::Error with Cloudflare's message;
# callers surface it to the admin.
class CloudflareDns
  class Error < StandardError; end

  BASE = URI("https://api.cloudflare.com/client/v4").freeze
  OPEN_TIMEOUT = 5
  READ_TIMEOUT = 15

  def self.enabled?
    ENV["CLOUDFLARE_API_TOKEN"].to_s.strip.present?
  end

  def initialize(token: ENV["CLOUDFLARE_API_TOKEN"].to_s.strip)
    raise Error, "CLOUDFLARE_API_TOKEN is not set" if token.empty?

    @token = token
  end

  def zone_id(name)
    zones = request(Net::HTTP::Get, "/zones", query: { name: name })
    zones.first&.fetch("id") ||
      raise(Error, "no zone named #{name} in this Cloudflare account (is the domain delegated to Cloudflare, and the token scoped to it?)")
  end

  def records(zone_id, type:, name:)
    request(Net::HTTP::Get, "/zones/#{zone_id}/dns_records", query: { type: type, name: name })
  end

  def create_record(zone_id, attrs)
    request(Net::HTTP::Post, "/zones/#{zone_id}/dns_records", body: attrs)
  end

  def update_record(zone_id, record_id, attrs)
    request(Net::HTTP::Put, "/zones/#{zone_id}/dns_records/#{record_id}", body: attrs)
  end

  private

  def request(verb, path, query: nil, body: nil)
    uri = URI("#{BASE}#{path}")
    uri.query = URI.encode_www_form(query) if query

    req = verb.new(uri)
    req["Authorization"] = "Bearer #{@token}"
    req["Content-Type"] = "application/json"
    req.body = body.to_json if body

    response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true,
                               open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT) do |http|
      http.request(req)
    end

    envelope = JSON.parse(response.body)
    unless envelope["success"]
      messages = Array(envelope["errors"]).map { |e| "#{e["code"]}: #{e["message"]}" }.join("; ")
      raise Error, messages.presence || "HTTP #{response.code}"
    end
    envelope["result"]
  rescue JSON::ParserError
    raise Error, "unexpected response (HTTP #{response&.code})"
  rescue Timeout::Error, SystemCallError, IOError, SocketError, OpenSSL::SSL::SSLError => e
    raise Error, "#{e.class}: #{e.message}"
  end
end
