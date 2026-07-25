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

  validates :name, presence: true, uniqueness: true,
                   format: { with: HOSTNAME, message: "must be a fully-qualified hostname (punycode for IDNs)", allow_blank: true }

  normalizes :name, with: ->(name) { name.to_s.strip.downcase.delete_suffix(".") }

  after_create_commit :activate
  after_destroy_commit :deactivate

  def dkim_key
    DkimKey.new(name)
  end

  # Is the domain in the exim file right now? (The file lives on our own
  # mount, so we can just read it.)
  def synced_to_exim?
    EximLocalDomains.current.include?(name)
  end

  private

  def activate
    dkim_key.ensure!
    EximLocalDomains.sync!
  end

  # force_empty: removing the last domain is explicit admin intent, even
  # though an empty list makes exim 550 all inbound mail.
  def deactivate
    dkim_key.retire!
    EximLocalDomains.sync!(force_empty: true)
  end
end
