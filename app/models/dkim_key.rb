# Value object around one domain's DKIM signing key - the PEM lives
# encrypted on the domains row (dkim_private_key), generated when the
# domain is created. This wraps it with the DNS-facing derivations the
# domain page and DnsCheck/DnsPublisher need.
class DkimKey
  BITS = 2048

  attr_reader :domain, :pem

  def initialize(domain, pem)
    @domain = domain
    @pem = pem
  end

  def self.generate_pem
    OpenSSL::PKey::RSA.new(BITS).to_pem
  end

  def present?
    pem.present?
  end

  def selector
    ENV.fetch("MAIL_ON_RAILS_DKIM_SELECTOR", "rail")
  end

  # The DNS TXT record that publishes the public key.
  def txt_name
    "#{selector}._domainkey.#{domain}"
  end

  def txt_value
    return nil unless present?

    # public_to_der = SubjectPublicKeyInfo DER, the format DKIM's p= wants.
    "v=DKIM1; k=rsa; p=#{Base64.strict_encode64(OpenSSL::PKey.read(pem).public_to_der)}"
  end
end
