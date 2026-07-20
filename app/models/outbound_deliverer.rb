require "net/smtp"
require "resolv"
require "dkim"

# Delivers one SmtpOutboundMessage to its recipient's mail server: resolves
# MX records, connects on port 25 with opportunistic STARTTLS, and speaks
# SMTP. When MAIL_ON_RAILS_SMARTHOST is set (host:port), every delivery is
# relayed through it instead - the way out while the host blocks port 25.
#
# Raises PermanentError (5xx, no such domain, null MX) or TransientError
# (4xx, timeouts, connection/DNS hiccups); the caller decides retry/bounce.
class OutboundDeliverer
  class PermanentError < StandardError; end
  class TransientError < StandardError; end

  OPEN_TIMEOUT = 20
  READ_TIMEOUT = 60

  def self.deliver(message)
    new.deliver(message)
  end

  def deliver(message)
    hosts = smarthost || mx_hosts(message.domain)
    errors = []

    hosts.each do |(host, port)|
      return send_via(host, port, message)
    rescue Net::SMTPFatalError, Net::SMTPSyntaxError => e
      # A 5xx from a live server is authoritative for this recipient -
      # trying the next MX would just get another rejection.
      raise PermanentError, "#{host}: #{e.message.strip}"
    rescue Net::SMTPServerBusy, Net::SMTPUnknownError, Net::SMTPAuthenticationError,
           OpenSSL::SSL::SSLError, IOError, SystemCallError, Timeout::Error => e
      errors << "#{host}: #{e.class}: #{e.message.strip}"
    end

    raise TransientError, errors.last || "no servers to try"
  end

  private

  def smarthost
    spec = ENV["MAIL_ON_RAILS_SMARTHOST"]
    return nil if spec.blank?

    host, port = spec.split(":")
    [ [ host, Integer(port || 25) ] ]
  end

  def mx_hosts(domain)
    mxs = Resolv::DNS.open do |dns|
      dns.timeouts = 10
      dns.getresources(domain, Resolv::DNS::Resource::IN::MX)
    end
    hosts = mxs.sort_by(&:preference).map { |mx| mx.exchange.to_s }

    # RFC 7505 null MX: the domain declares it never accepts mail.
    raise PermanentError, "#{domain} does not accept mail (null MX)" if hosts == [ "" ] || hosts == [ "." ]
    # RFC 5321: no MX records means fall back to the domain's own A record.
    hosts = [ domain ] if hosts.empty?

    hosts.map { |h| [ h, 25 ] }
  rescue Resolv::ResolvError, Resolv::ResolvTimeout => e
    raise TransientError, "DNS lookup for #{domain} failed: #{e.message}"
  end

  def send_via(host, port, message)
    smtp = Net::SMTP.new(host, port, starttls: :auto, tls_verify: false)
    smtp.open_timeout = OPEN_TIMEOUT
    smtp.read_timeout = READ_TIMEOUT
    args = { helo: helo_host }
    if ENV["MAIL_ON_RAILS_SMARTHOST_USER"].present?
      args.update(user: ENV["MAIL_ON_RAILS_SMARTHOST_USER"],
                  secret: ENV["MAIL_ON_RAILS_SMARTHOST_PASSWORD"], authtype: :plain)
    end
    smtp.start(**args) do |session|
      session.send_message(signed(message), message.mail_from, message.recipient)
    end
    true
  end

  # DKIM-signs with the sender domain's key when one exists under
  # MAIL_ON_RAILS_DKIM_DIR (<domain>.pem); the message goes out unsigned
  # otherwise. Key files are per-domain, so hosting more domains later
  # just means dropping in more keys (and DNS records).
  def signed(message)
    dir = ENV["MAIL_ON_RAILS_DKIM_DIR"]
    return message.data if dir.blank?

    domain = message.mail_from.to_s.split("@").last.to_s.downcase
    key_path = File.join(dir, "#{domain}.pem")
    return message.data unless File.exist?(key_path)

    Dkim.sign(message.data,
              domain: domain,
              selector: ENV.fetch("MAIL_ON_RAILS_DKIM_SELECTOR", "rail"),
              private_key: OpenSSL::PKey.read(File.read(key_path)))
  end

  # What we announce in EHLO. Remote servers check this resolves back to
  # us, so production sets it to the public mail hostname.
  def helo_host
    ENV.fetch("MAIL_ON_RAILS_HELO_HOST", Socket.gethostname)
  end
end
