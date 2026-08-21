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
module MailOnRails
  class Domain < Record
    encrypts :dkim_private_key
    encrypts :dkim_next_private_key
    # Lowercase ASCII/punycode FQDN.
    HOSTNAME = /\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/

    # Local part of the auto-created account DMARC aggregate reports are
    # mailed to (the rua= target on the domain page). MailroomMailbox
    # triggers report ingestion for mail delivered to it.
    DMARC_LOCAL_PART = "dmarc"

    # Local part of the auto-created account TLS-RPT failure reports are
    # mailed to (the TLS-RPT rua= target). MailroomMailbox triggers report
    # ingestion for mail delivered to it.
    TLS_RPT_LOCAL_PART = "tls-rpt"

    # Local parts of the auto-created operational account: RFC 5321
    # s4.5.1 requires every SMTP server to accept mail to postmaster, and
    # RFC 2142 expects abuse@ on any domain that sends mail. abuse@ and
    # mailer-daemon@ are aliases delivering into the postmaster account's
    # INBOX - mailer-daemon@ because our own DSN bounces use it as their
    # From:, so a user hitting reply on a bounce must reach the operator
    # rather than a rejection (the same arrangement as Postfix's stock
    # "mailer-daemon: postmaster" alias). All three also exist as aliases
    # at the mail-host subdomain (mail.<name>): external systems sometimes
    # address operational mail to the hostname they saw in HELO or PTR
    # rather than the organizational domain, and mail.<name> typically has
    # an A record but no MX, so RFC 5321's A-fallback delivers that mail
    # straight to us - where it answered "relaying denied" without these.
    POSTMASTER_LOCAL_PART = "postmaster"
    ABUSE_LOCAL_PART = "abuse"
    MAILER_DAEMON_LOCAL_PART = "mailer-daemon"

    # Local parts of the auto-created complaint feedback-loop account:
    # fbl@ receives ARF complaint reports from provider feedback loops
    # (MailroomMailbox triggers ingestion, which suppresses future mail to
    # complainants), and jmrp@ is an alias into the same INBOX so either
    # address can be registered with Microsoft's JMRP (SNDS). Both are
    # required addresses on every hosted domain.
    FBL_LOCAL_PART = "fbl"
    JMRP_LOCAL_PART = "jmrp"

    # Local part of the auto-created unsubscribe ingestion account: the
    # mailto: target of the List-Unsubscribe headers OutboundDeliverer
    # injects into outbound list mail (RFC 2369/8058). MailroomMailbox
    # triggers IngestUnsubscribeJob for mail delivered to it; the signed
    # token in the subject is the entire authorization.
    UNSUBSCRIBE_LOCAL_PART = "unsubscribe"

    # Local part of the auto-created VERP bounce account: outbound list
    # mail goes out with a signed bounce+m<id>-<mac>@<domain> envelope
    # sender (VerpAddress), asynchronous bounces come back to those
    # sub-addresses, the edge and mailroom resolve them into this
    # account, and IngestBounceJob suppresses on hard DSNs.
    BOUNCE_LOCAL_PART = "bounce"

    DKIM_KEY_BITS = 2048

    has_many :dmarc_reports, dependent: :delete_all
    has_many :tls_rpt_reports, dependent: :delete_all

    validates :name, presence: true, uniqueness: true,
                     format: { with: HOSTNAME, message: "must be a fully-qualified hostname (punycode for IDNs)", allow_blank: true }
    validate :bimi_svg_conforms

    normalizes :name, with: ->(name) { name.to_s.strip.downcase.delete_suffix(".") }

    before_create :generate_dkim_key
    after_create_commit :ensure_dmarc_account!
    after_create_commit :ensure_tls_rpt_account!
    after_create_commit :ensure_postmaster_account!
    after_create_commit :ensure_fbl_account!
    after_create_commit :ensure_unsubscribe_account!
    after_create_commit :ensure_bounce_account!
    # Fill the DNS pill cache without waiting for the hourly refresh (the
    # records won't exist yet, but "all red" beats "not checked").
    after_create_commit -> { DnsCheckRefreshJob.perform_later(self) }

    # Turbo broadcasts attach via ActiveSupport.on_load(:mail_on_rails_domain).

    def self.dmarc_ingestion_address?(email)
      local, _, domain_name = email.to_s.partition("@")
      local == DMARC_LOCAL_PART && exists?(name: domain_name)
    end

    def self.tls_rpt_ingestion_address?(email)
      local, _, domain_name = email.to_s.partition("@")
      local == TLS_RPT_LOCAL_PART && exists?(name: domain_name)
    end

    # Matches the fbl@ account address only - mail sent to the jmrp@ alias
    # resolves to the fbl@ account before this is consulted (the mailroom
    # routes by account, not by RCPT address), so both trigger ingestion.
    def self.fbl_ingestion_address?(email)
      local, _, domain_name = email.to_s.partition("@")
      local == FBL_LOCAL_PART && exists?(name: domain_name)
    end

    def self.unsubscribe_ingestion_address?(email)
      local, _, domain_name = email.to_s.partition("@")
      local == UNSUBSCRIBE_LOCAL_PART && exists?(name: domain_name)
    end

    def self.bounce_ingestion_address?(email)
      local, _, domain_name = email.to_s.partition("@")
      local == BOUNCE_LOCAL_PART && exists?(name: domain_name)
    end

    # The report-ingestion job for mail delivered to one of a hosted
    # domain's auto-created report accounts; nil for every other address.
    # Used by MailroomMailbox at delivery time and ScanPendingReportsJob
    # when catching up mail that arrived while virus scanning was off.
    def self.ingestion_job_for(email)
      return IngestDmarcReportJob if dmarc_ingestion_address?(email)
      return IngestTlsRptReportJob if tls_rpt_ingestion_address?(email)
      return IngestUnsubscribeJob if unsubscribe_ingestion_address?(email)
      return IngestBounceJob if bounce_ingestion_address?(email)

      IngestFblReportJob if fbl_ingestion_address?(email)
    end

    # The signing selector: the per-domain column once a rotation has
    # happened, the global static setting until then (pre-rotation rows
    # keep signing exactly as before the column existed).
    def dkim_selector
      self[:dkim_selector].presence || MailOnRails::Settings.static(:dkim_selector)
    end

    # The DNS TXT record that publishes the DKIM public key.
    def dkim_txt_name
      "#{dkim_selector}._domainkey.#{name}"
    end

    def dkim_txt_value
      dkim_txt_value_for(dkim_private_key)
    end

    # -- DKIM key rotation ------------------------------------------------
    #
    # Three-step lifecycle so signing never outruns DNS:
    #   stage_dkim_rotation!    mint a new key under a fresh selector
    #                           (next_* columns); publish its TXT
    #   promote_dkim_rotation!  switch signing to it - only once the TXT is
    #                           visible in public DNS; the old selector is
    #                           remembered as retired_*
    #   (revocation)            after a grace week the retired selector's
    #                           TXT is replaced with an empty p=, which
    #                           kills replays of its old signatures
    # RotateDkimKeysJob drives all three daily (publishing via Cloudflare);
    # stage/promote are also callable manually for DNS managed elsewhere.

    # How long a retired selector's TXT stays published before revocation:
    # long enough for in-flight mail and forwarding queues to verify.
    DKIM_RETIRE_GRACE = 7.days

    def dkim_staged?
      dkim_next_selector.present? && dkim_next_private_key.present?
    end

    def stage_dkim_rotation!
      return self if dkim_staged?

      update!(dkim_next_selector: next_dkim_selector_name,
              dkim_next_private_key: OpenSSL::PKey::RSA.new(DKIM_KEY_BITS).to_pem)
      self
    end

    def promote_dkim_rotation!
      raise ArgumentError, "no staged DKIM key to promote for #{name}" unless dkim_staged?

      update!(dkim_retired_selector: dkim_selector, dkim_retired_at: Time.current,
              dkim_selector: dkim_next_selector, dkim_private_key: dkim_next_private_key,
              dkim_next_selector: nil, dkim_next_private_key: nil,
              dkim_rotated_at: Time.current)
      self
    end

    def clear_retired_dkim!
      update!(dkim_retired_selector: nil, dkim_retired_at: nil)
    end

    # Due when the signing key's age (last rotation, or the row's creation
    # for never-rotated domains) exceeds +days+ and nothing is staged yet.
    def dkim_rotation_due?(days)
      days.to_i.positive? && !dkim_staged? &&
        (dkim_rotated_at || created_at) <= days.to_i.days.ago
    end

    def dkim_next_txt_name
      "#{dkim_next_selector}._domainkey.#{name}"
    end

    def dkim_next_txt_value
      dkim_txt_value_for(dkim_next_private_key)
    end

    def dkim_retired_txt_name
      "#{dkim_retired_selector}._domainkey.#{name}"
    end

    def dkim_txt_value_for(key)
      return nil if key.blank?

      # public_to_der = SubjectPublicKeyInfo DER, the format DKIM's p= wants.
      "v=DKIM1; k=rsa; p=#{Base64.strict_encode64(OpenSSL::PKey.read(key).public_to_der)}"
    end

    def dmarc_address
      "#{DMARC_LOCAL_PART}@#{name}"
    end

    def tls_rpt_address
      "#{TLS_RPT_LOCAL_PART}@#{name}"
    end

    def postmaster_address
      "#{POSTMASTER_LOCAL_PART}@#{name}"
    end

    def abuse_address
      "#{ABUSE_LOCAL_PART}@#{name}"
    end

    def mailer_daemon_address
      "#{MAILER_DAEMON_LOCAL_PART}@#{name}"
    end

    # The conventional mail-host name under this domain.
    def mail_host_name
      "mail.#{name}"
    end

    def fbl_address
      "#{FBL_LOCAL_PART}@#{name}"
    end

    def jmrp_address
      "#{JMRP_LOCAL_PART}@#{name}"
    end

    def unsubscribe_address
      "#{UNSUBSCRIBE_LOCAL_PART}@#{name}"
    end

    def bounce_address
      "#{BOUNCE_LOCAL_PART}@#{name}"
    end

    # -- BIMI (sender side) -------------------------------------------------
    # A self-asserted brand logo: the operator uploads an SVG (sanitized
    # on save), the engine serves it anonymously at bimi_logo_path, and
    # DnsPublisher publishes the default._bimi TXT pointing there.
    # Receivers that accept self-asserted BIMI (Yahoo, Fastmail) show it
    # once the domain's DMARC policy is enforcing; VMC/CMC evidence for
    # Gmail/Apple is a paid, out-of-band step this record leaves room for.

    def bimi_txt_name
      "default._bimi.#{name}"
    end

    def bimi_logo_path
      "/bimi/#{name}/logo.svg"
    end

    def bimi_txt_value(web_host)
      "v=BIMI1; l=https://#{web_host}#{bimi_logo_path};"
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

    # Same lifecycle as the report accounts. An alias is skipped when its
    # address is already taken (as an account or an alias on some other
    # account) - an operator's existing arrangement wins. That includes
    # postmaster@ itself: hosting mail.<x> after <x> finds the alias <x>'s
    # creation minted at its mail-host name and hangs everything off that
    # alias's account instead of colliding with it.
    def ensure_postmaster_account!
      account = EmailAccount.find_by(email: postmaster_address) ||
                EmailAlias.find_by(email: postmaster_address)&.email_account ||
                EmailAccount.create!(email: postmaster_address, name: "Postmaster", password: EmailAccount.generate_password)
      operational = [ POSTMASTER_LOCAL_PART, ABUSE_LOCAL_PART, MAILER_DAEMON_LOCAL_PART ]
      aliases = [ abuse_address, mailer_daemon_address ] + operational.map { |local| "#{local}@#{mail_host_name}" }
      aliases.each do |address|
        unless EmailAccount.exists?(email: address) || EmailAlias.exists?(email: address)
          EmailAlias.create!(email: address, email_account: account)
        end
      end
      account
    end

    # Same lifecycle as the postmaster account: fbl@ is the account (its
    # address routes ingestion - see ingestion_job_for), jmrp@ an alias
    # into it, skipped when the address is already taken so an operator's
    # existing arrangement wins.
    def ensure_fbl_account!
      account = EmailAccount.find_by(email: fbl_address) ||
                EmailAccount.create!(email: fbl_address, name: "Complaint reports", password: EmailAccount.generate_password)
      unless EmailAccount.exists?(email: jmrp_address) || EmailAlias.exists?(email: jmrp_address)
        EmailAlias.create!(email: jmrp_address, email_account: account)
      end
      account
    end

    # Same lifecycle as the fbl account: its own account (the mailroom
    # routes ingestion by account address - see ingestion_job_for), left
    # alone when the address is already taken.
    def ensure_unsubscribe_account!
      EmailAccount.find_by(email: unsubscribe_address) ||
        EmailAlias.find_by(email: unsubscribe_address)&.email_account ||
        EmailAccount.create!(email: unsubscribe_address, name: "Unsubscribe requests",
                             password: EmailAccount.generate_password)
    end

    # Same lifecycle again: VERP bounces resolve into this account (the
    # raw DSNs stay inspectable here), and its address routes ingestion.
    def ensure_bounce_account!
      EmailAccount.find_by(email: bounce_address) ||
        EmailAlias.find_by(email: bounce_address)&.email_account ||
        EmailAccount.create!(email: bounce_address, name: "Bounce processing (VERP)",
                             password: EmailAccount.generate_password)
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

    # Date-stamped so the DNS history reads at a glance; the time suffix
    # only appears for a second rotation staged the same day.
    def next_dkim_selector_name
      base = "#{MailOnRails::Settings.static(:dkim_selector)}-#{Time.current.strftime("%Y%m%d")}"
      [ dkim_selector, dkim_retired_selector ].include?(base) ? "#{base}-#{Time.current.strftime("%H%M%S")}" : base
    end

    # The uploaded logo is served to the whole internet and rendered by
    # receivers' mail UIs; it passes the same strict profile we hold
    # remote senders' logos to, and the sanitized serialization is what
    # gets stored.
    def bimi_svg_conforms
      return if bimi_svg.blank?

      self.bimi_svg = BimiSvg.sanitize(bimi_svg)
    rescue BimiSvg::Invalid => e
      errors.add(:bimi_svg, e.message)
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_domain, MailOnRails::Domain
