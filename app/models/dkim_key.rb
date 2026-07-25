# The DKIM signing key for one domain: <domain>.pem under
# MAIL_ON_RAILS_DKIM_DIR - the exact path OutboundDeliverer#signed reads,
# so ensure!/retire! directly start/stop signing for the domain. With the
# dir unset (dev/test default) every operation is a no-op.
class DkimKey
  BITS = 2048

  attr_reader :domain

  def initialize(domain)
    @domain = domain
  end

  # Generate a key if the domain has none. An existing key is never
  # touched (its public half is published in DNS); a retired key is
  # restored instead of generating a new one, so re-adding a domain keeps
  # its published DNS record valid.
  def ensure!
    return if dir.blank? || present?

    if File.exist?(retired_path)
      File.rename(retired_path, path)
    else
      key = OpenSSL::PKey::RSA.new(BITS)
      tmp = File.join(dir, ".#{domain}.pem.#{Process.pid}")
      File.write(tmp, key.to_pem)
      File.chmod(0o600, tmp)
      File.rename(tmp, path)
    end
  end

  # Stop signing (OutboundDeliverer's File.exist? goes false) but keep the
  # key material - mail signed with it may still be in flight, and the
  # domain may come back.
  def retire!
    return if dir.blank?

    File.rename(path, retired_path) if present?
  end

  def present?
    dir.present? && File.exist?(path)
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
    public_der = OpenSSL::PKey.read(File.read(path)).public_to_der
    "v=DKIM1; k=rsa; p=#{Base64.strict_encode64(public_der)}"
  end

  private

  def dir
    ENV["MAIL_ON_RAILS_DKIM_DIR"]
  end

  def path
    File.join(dir, "#{domain}.pem")
  end

  def retired_path
    "#{path}.disabled"
  end
end
