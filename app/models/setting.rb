# App-wide operational knobs, one row per key, read through typed accessors
# so callers never see the string storage. A missing row means the default -
# nothing seeds this table.
class Setting < ApplicationRecord
  validates :key, presence: true, uniqueness: true

  # How long a message sits in Trash before the daily PurgeTrashJob deletes
  # it permanently. Counted from when the message entered Trash (the row's
  # created_at - moving creates a fresh row), not from when it was received.
  TRASH_RETENTION_DEFAULT_DAYS = 30

  def self.trash_retention_days
    Integer(find_by(key: "trash_retention_days")&.value || TRASH_RETENTION_DEFAULT_DAYS)
  end

  # Raises ArgumentError on non-numeric or non-positive input - the one
  # caller (SettingsController#update) turns that into a flash alert.
  def self.trash_retention_days=(days)
    days = Integer(days)
    raise ArgumentError, "must be at least 1 day" if days < 1

    find_or_initialize_by(key: "trash_retention_days").update!(value: days.to_s)
  end

  # The hostname this server announces on SMTP connections (220 banner,
  # HELO/EHLO replies) and sends as its own HELO when delivering outbound
  # mail. Precedence: this setting, then SMTP_HELO_HOST, then the system
  # hostname. Receiving servers compare it to our public DNS, so it should
  # be the machine's mail FQDN.
  #
  # RFC 1123 host name: dot-separated alnum-and-hyphen labels, no label
  # starting or ending with a hyphen.
  HELO_HOSTNAME_PATTERN = /\A(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\z/

  # The DB row alone - what the settings form edits; nil means "no
  # override, fall through to the environment".
  def self.smtp_helo_hostname_override
    find_by(key: "smtp_helo_hostname")&.value
  end

  # The configured name (override or env), nil when neither is set - the
  # DNS publisher/checker want exactly this, never a fallback guess.
  def self.smtp_helo_hostname
    smtp_helo_hostname_override || ENV["SMTP_HELO_HOST"].to_s.strip.downcase.presence
  end

  # What actually goes on the wire when nothing is configured.
  def self.effective_smtp_helo_hostname
    smtp_helo_hostname || Socket.gethostname
  end

  # Blank clears the override; anything else must parse as a hostname.
  # Raises ArgumentError on junk - SettingsController#update turns that
  # into a flash alert.
  def self.smtp_helo_hostname=(name)
    name = name.to_s.strip.downcase
    if name.empty?
      where(key: "smtp_helo_hostname").delete_all
    elsif name.length > 255 || !name.match?(HELO_HOSTNAME_PATTERN)
      raise ArgumentError, "must be a hostname like mail.example.com"
    else
      find_or_initialize_by(key: "smtp_helo_hostname").update!(value: name)
    end
  end
end
