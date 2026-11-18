require "net/http"
require "socket"
require "ipaddr"
require "timeout"
require "mail_on_rails/netserv/ip"

# Fetches a BIMI logo (the l= URL of a sender's default._bimi record).
# The URL comes from DNS an arbitrary sender controls and the fetch runs
# from this server's network position, so every step is an SSRF surface.
# Same construction as the MTA-STS policy fetch (MtaStsPolicy):
#
#   - https only;
#   - the host is resolved once and refused outright if ANY address is in
#     Netserv::NON_ROUTABLE (loopback, RFC 1918, link-local, CGNAT,
#     0.0.0.0/8, documentation, v4-mapped, ULA - a container network);
#   - the connection is pinned to an address that was vetted, with TLS
#     still verified against the hostname - resolving again at connect
#     time would let the name answer "public" to the check and "10.0.0.1"
#     to the socket;
#   - the body is streamed and abandoned the moment it passes the logo
#     ceiling, and the whole exchange has a deadline;
#   - a redirect is a new URL: validated, vetted and pinned from scratch.
module MailOnRails
  class BimiFetcher
    class Error < StandardError; end
    # One address of the logo host could not be connected to at all; the
    # next address is tried before giving up.
    class Unreachable < Error; end

    MAX_REDIRECTS = 2
    TIMEOUT = 5
    # Bound on one request, connect to last byte: the per-read timeout
    # alone lets a server trickle a byte every few seconds for hours.
    DEADLINE = 20

    Redirect = Struct.new(:location)

    def self.fetch(url)
      new.fetch(url)
    end

    def fetch(url, redirects_left: MAX_REDIRECTS)
      uri = https_uri(url)
      outcome = request(uri)
      return outcome unless outcome.is_a?(Redirect)

      raise Error, "too many redirects" unless redirects_left.positive?
      raise Error, "redirect without a location" if outcome.location.empty?

      fetch(URI.join(uri, outcome.location).to_s, redirects_left: redirects_left - 1)
    rescue URI::InvalidURIError => e
      raise Error, "#{e.class}: #{e.message.to_s.truncate(120)}"
    end

    private

    def https_uri(url)
      uri = URI.parse(url.to_s)
      raise Error, "logo URL must be https" unless uri.is_a?(URI::HTTPS)
      raise Error, "logo URL has no host" if uri.host.to_s.empty?

      uri
    end

    # Tries the host's addresses in resolver order and moves to the next
    # only when the address itself is unreachable. Anything the server
    # actually said (a status, a TLS failure, too many bytes) is final.
    def request(uri)
      unreachable = nil
      vetted_addresses(uri).each do |address|
        return request_from(uri, address)
      rescue Unreachable => e
        unreachable = e
      end
      raise unreachable
    end

    # The body (String) or a Redirect.
    def request_from(uri, address)
      http = Net::HTTP.new(uri.hostname, uri.port)
      # The socket goes to the address that was vetted; SNI and the
      # certificate check still use the hostname (net/http keeps the two
      # apart when ipaddr is set).
      http.ipaddr = address
      http.use_ssl = true # WebPKI-verified by default; a bad cert is a failed fetch
      http.open_timeout = TIMEOUT
      http.read_timeout = TIMEOUT
      http.max_retries = 0
      # identity: the cap below must count the bytes we keep, not a
      # compressed stream net/http would inflate for us.
      headers = { "User-Agent" => "mail_on_rails BIMI fetcher", "Accept-Encoding" => "identity" }
      Timeout.timeout(DEADLINE) do
        http.request_get(uri.request_uri, headers) do |response|
          case response
          when Net::HTTPSuccess
            return read_capped(response)
          when Net::HTTPRedirection
            return Redirect.new(response["location"].to_s)
          else
            raise Error, "HTTP #{response.code} fetching the logo"
          end
        end
      end
    rescue OpenSSL::SSL::SSLError => e
      raise Error, "TLS: #{e.message.to_s.truncate(120)}"
    rescue Net::OpenTimeout, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH,
           Errno::EADDRNOTAVAIL, Errno::ETIMEDOUT, SocketError => e
      raise Unreachable, "#{address}: #{e.class}: #{e.message.to_s.truncate(120)}"
    rescue Timeout::Error, IOError, SystemCallError, Net::ProtocolError => e
      raise Error, "#{e.class}: #{e.message.to_s.truncate(120)}"
    end

    # Streamed, and abandoned at the ceiling the sanitizer enforces:
    # response.body would buffer whatever the server chose to send before
    # any size check could run. (BimiSvg is referenced lazily - load order
    # between the two classes is unordered outside the engine.)
    def read_capped(response)
      body = +"".b
      response.read_body do |chunk|
        body << chunk
        raise Error, "logo exceeds #{BimiSvg::MAX_BYTES / 1024} KB" if body.bytesize > BimiSvg::MAX_BYTES
      end
      body
    end

    # The host's addresses in resolver order, refused outright when ANY of
    # them is non-routable: a mixed public/private RRset is hostile by
    # construction, not a tie to break in the sender's favor.
    def vetted_addresses(uri)
      addresses = resolve(uri.hostname, uri.port)
      raise Error, "logo host does not resolve" if addresses.empty?

      addresses.each do |address|
        next if routable?(address.sub(/%.+\z/, "")) # minus any IPv6 zone id

        raise Error, "logo host resolves to non-public address space (#{address})"
      end
      addresses
    end

    def resolve(host, port)
      Addrinfo.getaddrinfo(host, port, nil, :STREAM).map(&:ip_address).uniq
    rescue SocketError
      []
    end

    def routable?(address)
      Netserv.routable?(address)
    end
  end
end
