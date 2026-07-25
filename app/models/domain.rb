# A domain we host mail for. Creating/destroying one takes effect live:
# the exim edge's local_domains list is a file on a volume shared with this
# app (see EximLocalDomains), re-read by exim per connection - no restart.
# Creation also ensures a DKIM signing key exists (see DkimKey), closing
# the gap where a new domain silently sent unsigned mail.
#
# A domain here only makes exim treat recipients as local and enables DKIM
# signing; DNS (MX/SPF/DKIM TXT - shown on the domain page) and
# EmailAccount rows are still needed before mail flows.
class Domain < ApplicationRecord
  # Lowercase ASCII/punycode FQDN. Also keeps Exim list metacharacters
  # (':', '!', '*', whitespace) out of the local_domains file.
  HOSTNAME = /\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/

  # Local part of the auto-created account DMARC aggregate reports are
  # mailed to (the rua= target on the domain page). MailroomMailbox
  # triggers report ingestion for mail delivered to it.
  DMARC_LOCAL_PART = "dmarc"

  has_many :dmarc_reports, dependent: :delete_all

  validates :name, presence: true, uniqueness: true,
                   format: { with: HOSTNAME, message: "must be a fully-qualified hostname (punycode for IDNs)", allow_blank: true }

  normalizes :name, with: ->(name) { name.to_s.strip.downcase.delete_suffix(".") }

  after_create_commit :activate
  after_destroy_commit :deactivate

  def self.dmarc_ingestion_address?(email)
    local, _, domain_name = email.to_s.partition("@")
    local == DMARC_LOCAL_PART && exists?(name: domain_name)
  end

  def dkim_key
    DkimKey.new(name)
  end

  def dmarc_address
    "#{DMARC_LOCAL_PART}@#{name}"
  end

  # The reports account. Auto-created on domain creation with a random
  # password (reset it in the accounts UI for IMAP access to the raw
  # reports); left in place on domain destroy so history survives.
  def ensure_dmarc_account!
    EmailAccount.find_by(email: dmarc_address) ||
      EmailAccount.create!(email: dmarc_address, name: "DMARC reports", password: SecureRandom.base58(24))
  end

  # Is the domain in the exim file right now? (The file lives on our own
  # mount, so we can just read it.)
  def synced_to_exim?
    EximLocalDomains.current.include?(name)
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

  def activate
    dkim_key.ensure!
    ensure_dmarc_account!
    EximLocalDomains.sync!
  end

  # force_empty: removing the last domain is explicit admin intent, even
  # though an empty list makes exim 550 all inbound mail.
  def deactivate
    dkim_key.retire!
    EximLocalDomains.sync!(force_empty: true)
  end
end
