# Writes the banned_ips file (one IP or CIDR per line) at
# MAIL_ON_RAILS_BANNED_IPS_FILE, on the mailconf volume so bans survive
# container replacement. The in-process SMTP and IMAP listeners read it
# (their Denylist re-parses on mtime change) - so a ban takes effect
# within seconds of the row committing, with no restart. With the env var
# unset (dev/test default) syncing is a no-op.
#
# Semantics: an EMPTY file means "no bans" and is the normal steady
# state; a MISSING file also just means "no bans" to the listeners, but
# the entrypoint's banned_ips:sync writes it at boot so existing ban rows
# are enforced from the first connection on a fresh volume.
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
      File.chmod(0o644, tmp)
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
