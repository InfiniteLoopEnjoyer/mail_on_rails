# A domain we host mail for. Creating/destroying one takes effect live:
# the in-process SMTP server consults this table at RCPT time
# (Store::SmtpBackend#local_rcpts), so a recipient in a hosted domain with
# no account answers "no such user" instead of "relaying denied".
# Creation also mints the DKIM signing key, stored encrypted on this row
# (dkim_private_key) - so no domain ever silently sends unsigned. The key
# dies with the row: re-adding a domain mints a NEW key, so the DKIM TXT
# must be republished then.
#
# A domain here only makes the SMTP server treat recipients as local and
# enables DKIM signing; DNS (MX/SPF/DKIM TXT - shown on the domain page)
# and EmailAccount rows are still needed before mail flows.
class Domain < ApplicationRecord
  encrypts :dkim_private_key
  # Lowercase ASCII/punycode FQDN.
  HOSTNAME = /\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/

  # Local part of the auto-created account DMARC aggregate reports are
  # mailed to (the rua= target on the domain page). MailroomMailbox
  # triggers report ingestion for mail delivered to it.
  DMARC_LOCAL_PART = "dmarc"

  # Local part of the auto-created account TLS-RPT failure reports are
  # mailed to (the TLS-RPT rua= target). Kept for human review only -
  # nothing parses these.
  TLS_RPT_LOCAL_PART = "tls-rpt"

  DKIM_KEY_BITS = 2048

  has_many :dmarc_reports, dependent: :delete_all

  validates :name, presence: true, uniqueness: true,
                   format: { with: HOSTNAME, message: "must be a fully-qualified hostname (punycode for IDNs)", allow_blank: true }

  normalizes :name, with: ->(name) { name.to_s.strip.downcase.delete_suffix(".") }

  before_create :generate_dkim_key
  after_create_commit :ensure_dmarc_account!
  after_create_commit :ensure_tls_rpt_account!
  # Fill the DNS pill cache without waiting for the hourly refresh (the
  # records won't exist yet, but "all red" beats "not checked").
  after_create_commit -> { DnsCheckRefreshJob.perform_later(self) }

  def self.dmarc_ingestion_address?(email)
    local, _, domain_name = email.to_s.partition("@")
    local == DMARC_LOCAL_PART && exists?(name: domain_name)
  end

  def dkim_selector
    ENV.fetch("MAIL_ON_RAILS_DKIM_SELECTOR", "rail")
  end

  # The DNS TXT record that publishes the DKIM public key.
  def dkim_txt_name
    "#{dkim_selector}._domainkey.#{name}"
  end

  def dkim_txt_value
    return nil if dkim_private_key.blank?

    # public_to_der = SubjectPublicKeyInfo DER, the format DKIM's p= wants.
    "v=DKIM1; k=rsa; p=#{Base64.strict_encode64(OpenSSL::PKey.read(dkim_private_key).public_to_der)}"
  end

  def dmarc_address
    "#{DMARC_LOCAL_PART}@#{name}"
  end

  def tls_rpt_address
    "#{TLS_RPT_LOCAL_PART}@#{name}"
  end

  # The cached DnsCheck results (jsonb; see DnsCheck.refresh! for when it
  # refreshes), rehydrated into Check structs for the index pills. Empty
  # until the first check runs.
  def cached_dns_checks
    Array(dns_checks).map do |c|
      DnsCheck::Check.new(record: c["record"], status: c["status"].to_sym, found: c["found"], note: c["note"])
    end
  end

  # The reports account. Auto-created on domain creation with a random
  # password (generate a new one in the accounts UI for IMAP access to the
  # raw reports); left in place on domain destroy so history survives.
  def ensure_dmarc_account!
    EmailAccount.find_by(email: dmarc_address) ||
      EmailAccount.create!(email: dmarc_address, name: "DMARC reports", password: EmailAccount.generate_password)
  end

  # Same lifecycle as the dmarc account. Also called by DnsPublisher when
  # it first publishes the TLS-RPT record, so domains created before
  # TLS-RPT support get the account backfilled.
  def ensure_tls_rpt_account!
    EmailAccount.find_by(email: tls_rpt_address) ||
      EmailAccount.create!(email: tls_rpt_address, name: "TLS reports", password: EmailAccount.generate_password)
  end

  # Escalation advice for the readiness indicator, from the last 30 days
  # of aggregate reports (DmarcReport.stats) and the published record.
  # Deliberately advice, not automation: flipping to p=reject on a bad
  # heuristic rejects legitimate mail, so a human publishes the change.
  MIN_ALIGNED_PCT = 99.5
  MIN_SPAN_DAYS = 14
  MIN_MESSAGES = 25

  def dmarc_advice(stats, published)
    policy = published.to_s[/\bp\s*=\s*(\w+)/i, 1]&.downcase
    return [ :publish, "No DMARC record found in DNS. Publish the TXT record below (p=none) so receivers start sending aggregate reports to #{dmarc_address}." ] if policy.nil?
    return [ :done, "Policy is p=reject - fully tightened. Keep an eye on the reports for new legitimate sources." ] if policy == "reject"
    return [ :waiting, "Record published (p=#{policy}) but no aggregate reports received yet. Reporters send at most one per day - check back tomorrow." ] if stats[:total].zero?

    ready = stats[:aligned_pct] >= MIN_ALIGNED_PCT &&
            stats[:span_days] >= MIN_SPAN_DAYS &&
            stats[:total] >= MIN_MESSAGES
    if ready
      next_policy = policy == "none" ? "quarantine" : "reject"
      [ :ready, "#{stats[:aligned_pct].round(1)}% of #{stats[:total]} messages aligned over #{stats[:span_days]} days - safe to tighten to p=#{next_policy}." ]
    else
      [ :monitoring, "Keep monitoring: #{stats[:total]} messages, #{stats[:aligned_pct].round(1)}% aligned over #{stats[:span_days]} days " \
                     "(want >=#{MIN_ALIGNED_PCT}% across >=#{MIN_MESSAGES} messages spanning >=#{MIN_SPAN_DAYS} days before tightening p=#{policy})." ]
    end
  end

  private

  # ||= so an import (e.g. restoring a dumped row) keeps its key.
  def generate_dkim_key
    self.dkim_private_key ||= OpenSSL::PKey::RSA.new(DKIM_KEY_BITS).to_pem
  end
end
