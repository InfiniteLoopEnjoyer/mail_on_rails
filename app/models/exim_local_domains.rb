# Writes the exim edge's local_domains file (one domain per line) on the
# shared mailconf volume - MAIL_ON_RAILS_EXIM_DOMAINS_FILE, mounted in the
# exim container at /var/lib/exim4/dynamic/local_domains, where its
# lsearch domainlist re-reads it per connection. With the env var unset
# (dev/test default) syncing is a no-op.
#
# Semantics that matter: a MISSING file makes exim defer (4xx, retried),
# but an EMPTY file means "no local domains" and permanently 550s all
# inbound mail - so an empty list is refused unless the caller forces it
# (deleting the last domain).
class EximLocalDomains
  class Error < StandardError; end

  # Atomic: tmp file in the same directory + rename, so exim sees the old
  # or the new list, never a torn write.
  def self.sync!(force_empty: false)
    path = ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"]
    return :skipped if path.blank?

    names = Domain.order(:name).pluck(:name)
    if names.empty? && !force_empty
      raise Error, "refusing to write an empty domain list (exim would 550 all inbound mail)"
    end

    dir = File.dirname(path)
    unless File.writable?(dir)
      raise Error, "#{dir} is not writable (mailconf volume unmounted?)"
    end

    tmp = File.join(dir, ".local_domains.#{Process.pid}.#{SecureRandom.hex(4)}")
    begin
      File.open(tmp, "w") do |f|
        f.write(names.join("\n") + "\n")
        f.fsync
      end
      File.chmod(0o644, tmp) # the exim user must be able to read it
      File.rename(tmp, path)
    ensure
      File.unlink(tmp) if File.exist?(tmp)
    end
    :written
  end

  # The domains exim currently accepts, straight from the file.
  def self.current
    path = ENV["MAIL_ON_RAILS_EXIM_DOMAINS_FILE"]
    return [] if path.blank? || !File.exist?(path)

    File.readlines(path, chomp: true).map(&:strip).reject(&:empty?)
  end
end
