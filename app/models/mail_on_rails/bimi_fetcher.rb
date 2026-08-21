require "net/http"
require "resolv"
require "ipaddr"

# Fetches a BIMI logo (the l= URL of a sender's default._bimi record).
# The URL comes from DNS an arbitrary sender controls, so this is an
# SSRF surface: https only, the host must resolve to public address
# space, redirects are bounded and re-validated, and the body is
# size-capped before it ever reaches the SVG sanitizer. (Residual risk
# is a post-validation DNS rebind, the same posture as the settings
# schema's scanner-address validation - connect-time pinning is not
# attempted, and the fetched bytes are sanitized regardless.)
module MailOnRails
  class BimiFetcher
    class Error < StandardError; end

    MAX_REDIRECTS = 2
    TIMEOUT = 5

    def self.fetch(url)
      new.fetch(url)
    end

    def fetch(url, redirects_left: MAX_REDIRECTS)
      uri = validated_uri(url)
      response = get(uri)
      case response
      when Net::HTTPSuccess
        body = response.body.to_s
        # Same ceiling the sanitizer enforces, applied before the bytes
        # reach the XML parser. (Referenced lazily - load order between
        # the two classes is unordered outside the engine.)
        raise Error, "logo exceeds #{BimiSvg::MAX_BYTES / 1024} KB" if body.bytesize > BimiSvg::MAX_BYTES

        body
      when Net::HTTPRedirection
        raise Error, "too many redirects" unless redirects_left.positive?

        location = response["location"].to_s
        raise Error, "redirect without a location" if location.empty?

        fetch(URI.join(uri, location).to_s, redirects_left: redirects_left - 1)
      else
        raise Error, "HTTP #{response.code} fetching the logo"
      end
    rescue Timeout::Error, SystemCallError, IOError, SocketError, OpenSSL::SSL::SSLError,
           Net::ProtocolError, URI::InvalidURIError => e
      raise Error, "#{e.class}: #{e.message.to_s.truncate(120)}"
    end

    private

    def validated_uri(url)
      uri = URI.parse(url.to_s)
      raise Error, "logo URL must be https" unless uri.is_a?(URI::HTTPS)
      raise Error, "logo URL has no host" if uri.host.to_s.empty?

      addresses = Resolv.getaddresses(uri.host).filter_map do |address|
        IPAddr.new(address)
      rescue IPAddr::InvalidAddressError
        nil
      end
      raise Error, "logo host does not resolve" if addresses.empty?
      if addresses.any? { |a| a.loopback? || a.private? || a.link_local? }
        raise Error, "logo host resolves to non-public address space"
      end

      uri
    end

    def get(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = TIMEOUT
      http.read_timeout = TIMEOUT
      http.max_retries = 0
      http.request(Net::HTTP::Get.new(uri.request_uri, { "User-Agent" => "mail_on_rails BIMI fetcher" }))
    end
  end
end
