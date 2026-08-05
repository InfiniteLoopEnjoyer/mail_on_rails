# Writes the banned_ips file (one IP or CIDR per line) on the shared
# mailconf volume - MAIL_ON_RAILS_BANNED_IPS_FILE. Two daemons read it:
# exim (an absolute-filename host list in its connect ACL, re-read per
# connection because exim forks per connection) and the IMAP daemon (its
# Denylist re-parses on mtime change) - so a ban takes effect within
# seconds of the row committing, with no restart anywhere. With the env
# var unset (dev/test default) syncing is a no-op.
#
# Semantics that matter, and they're the inverse of the recipients file:
# an EMPTY file means "no bans" and is the normal steady state, while a
# MISSING file makes exim's host-list check error and the connect ACL
# defer every connection with 4xx - which is why the exim entrypoint seeds
# an empty file on fresh volumes and this writer runs at deploy time.
class BannedIpsFile
  class Error < StandardError; end

  # Atomic: tmp file in the same directory + rename, so readers see the
  # old or the new list, never a torn write.
  def self.sync!
    path = ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"]
    return :skipped if path.blank?

    cidrs = self.cidrs

    dir = File.dirname(path)
    unless File.writable?(dir)
      raise Error, "#{dir} is not writable (mailconf volume unmounted?)"
    end

    tmp = File.join(dir, ".banned_ips.#{Process.pid}.#{SecureRandom.hex(4)}")
    begin
      File.open(tmp, "w") do |f|
        f.write(cidrs.map { |cidr| "#{cidr}\n" }.join)
        f.fsync
      end
      File.chmod(0o644, tmp) # the exim and imap users must be able to read it
      File.rename(tmp, path)
    ensure
      File.unlink(tmp) if File.exist?(tmp)
    end
    :written
  end

  def self.cidrs
    BannedIp.order(:cidr).pluck(:cidr)
  end

  # The bans the mail edges currently act on, straight from the file.
  def self.current
    path = ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"]
    return [] if path.blank? || !File.exist?(path)

    File.readlines(path, chomp: true).map(&:strip).reject(&:empty?)
  end
end
