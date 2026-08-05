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
end
