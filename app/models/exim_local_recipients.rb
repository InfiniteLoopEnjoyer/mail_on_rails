# Writes the exim edge's local_recipients file (one address per line) on
# the shared mailconf volume - MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE, mounted
# in the exim container at /var/lib/exim4/dynamic/local_recipients, where
# acl_rcpt lsearches it per RCPT command. This replaces the old per-RCPT
# HTTP round trip to internal/rcpt_check: exim answers "is this a real
# account?" from the file alone. With the env var unset (dev/test default)
# syncing is a no-op.
#
# Semantics that matter: a MISSING file makes exim's lookup (and so the
# RCPT) defer with 4xx - senders retry, nothing is lost - while an EMPTY
# file means "no local accounts" and 550s every recipient in a hosted
# domain. Unlike EximLocalDomains, an empty list needs no force flag: with
# zero EmailAccount rows a 550 is the same (correct) answer the rcpt_check
# endpoint used to give. Addresses are already normalized (strip +
# downcase) by EmailAccount and EmailAlias, matching exim's caseless
# address-list lookup.
class EximLocalRecipients
  class Error < StandardError; end

  # Atomic: tmp file in the same directory + rename, so exim sees the old
  # or the new list, never a torn write.
  def self.sync!
    path = ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"]
    return :skipped if path.blank?

    addresses = self.addresses

    dir = File.dirname(path)
    unless File.writable?(dir)
      raise Error, "#{dir} is not writable (mailconf volume unmounted?)"
    end

    tmp = File.join(dir, ".local_recipients.#{Process.pid}.#{SecureRandom.hex(4)}")
    begin
      File.open(tmp, "w") do |f|
        f.write(addresses.join("\n") + "\n")
        f.fsync
      end
      File.chmod(0o644, tmp) # the exim user must be able to read it
      File.rename(tmp, path)
    ensure
      File.unlink(tmp) if File.exist?(tmp)
    end
    :written
  end

  # Every address exim should accept at RCPT time: account addresses plus
  # aliases (extra addresses that deliver into an account's INBOX). The
  # cross-model uniqueness validations keep the two sets disjoint.
  def self.addresses
    (EmailAccount.pluck(:email) + EmailAlias.pluck(:email)).sort
  end

  # The addresses exim currently accepts, straight from the file.
  def self.current
    path = ENV["MAIL_ON_RAILS_EXIM_RECIPIENTS_FILE"]
    return [] if path.blank? || !File.exist?(path)

    File.readlines(path, chomp: true).map(&:strip).reject(&:empty?)
  end
end
