# The MTA-STS policy (RFC 8461) this server publishes for its hosted
# domains. Senders that support MTA-STS see the _mta-sts TXT record
# (published by DnsPublisher), fetch the policy from
# https://mta-sts.<domain>/.well-known/mta-sts.txt (MtaStsController -
# the publisher CNAMEs that host at this app), and thereafter require
# verified TLS to the mx named below. The policy is identical for every
# hosted domain: one mx, one mode.
#
# The TXT record's id must change whenever the policy file changes
# (senders re-fetch only on a new id), so it is derived from the policy
# body itself - change MAIL_ON_RAILS_MTA_STS_MODE / _MAX_AGE or the SMTP
# hostname and the next "Publish DNS" bumps the id automatically.
class MtaSts
  MODES = %w[testing enforce none].freeze
  # RFC 8461 3.2: max_age is capped at one year (31557600).
  MAX_AGE_RANGE = (3600..31_557_600)

  # testing = senders report TLS failures (see the TLS-RPT record) but
  # still deliver; flip to "enforce" once the reports come back clean.
  # Validated at boot (config/initializers/mta_sts.rb) so a typo fails
  # the deploy instead of 500ing the policy endpoint.
  def self.mode
    value = ENV.fetch("MAIL_ON_RAILS_MTA_STS_MODE", "testing")
    unless MODES.include?(value)
      raise ArgumentError, "MAIL_ON_RAILS_MTA_STS_MODE must be one of #{MODES.join("/")}, got #{value.inspect}"
    end

    value
  end

  # How long senders cache the policy. Short while testing (a bad policy
  # must age out fast); a week under enforce, where flapping back to a
  # short cache would soften the guarantee. An explicit
  # MAIL_ON_RAILS_MTA_STS_MAX_AGE overrides both defaults.
  def self.max_age
    explicit = ENV["MAIL_ON_RAILS_MTA_STS_MAX_AGE"]
    return mode == "enforce" ? 604_800 : 86_400 unless explicit

    value = begin
      Integer(explicit)
    rescue ArgumentError
      raise ArgumentError, "MAIL_ON_RAILS_MTA_STS_MAX_AGE must be an integer, got #{explicit.inspect}"
    end
    unless MAX_AGE_RANGE.cover?(value)
      raise ArgumentError, "MAIL_ON_RAILS_MTA_STS_MAX_AGE must be in #{MAX_AGE_RANGE}, got #{value}"
    end

    value
  end

  def self.configured?
    Setting.smtp_helo_hostname.present?
  end

  # RFC 8461 4.1: key/value lines, CRLF-terminated.
  def self.policy
    [ "version: STSv1", "mode: #{mode}", "mx: #{Setting.smtp_helo_hostname}", "max_age: #{max_age}" ]
      .map { |line| "#{line}\r\n" }.join
  end

  # 1-32 alphanumerics per RFC 8461 3.1.
  def self.policy_id
    Digest::SHA256.hexdigest(policy).first(12)
  end

  def self.txt_record
    "v=STSv1; id=#{policy_id}"
  end

  def self.policy_host(domain)
    "mta-sts.#{domain.name}"
  end
end
