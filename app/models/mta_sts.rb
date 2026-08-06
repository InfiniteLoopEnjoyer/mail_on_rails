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
# body itself - edit MODE/MAX_AGE or the SMTP hostname and the next
# "Publish DNS" bumps the id automatically.
class MtaSts
  # testing = senders report TLS failures (see the TLS-RPT record) but
  # still deliver; flip to "enforce" once the reports come back clean.
  MODE = "testing"
  # How long senders cache the policy. Keep short while testing; raise
  # (e.g. to 604800) alongside mode: enforce.
  MAX_AGE = 86400

  def self.configured?
    Setting.smtp_helo_hostname.present?
  end

  # RFC 8461 4.1: key/value lines, CRLF-terminated.
  def self.policy
    [ "version: STSv1", "mode: #{MODE}", "mx: #{Setting.smtp_helo_hostname}", "max_age: #{MAX_AGE}" ]
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
