# One row per admin action (see the Auditing controller concern): who did
# what to what, from where, when. Rows are immutable and are never pruned -
# an audit trail with a retention window is a suggestion, not a record.
#
# The subject association is polymorphic and optional both ways: the
# subject may be deleted later (the label snapshot keeps the row legible),
# and some actions have no subject at all (settings changes).
class AuditEvent < ApplicationRecord
  belongs_to :user, optional: true
  belongs_to :subject, polymorphic: true, optional: true

  validates :user_email, :action, presence: true

  scope :newest_first, -> { order(created_at: :desc, id: :desc) }

  # Immutable once written: an editable audit log audits nothing.
  def readonly? = persisted?

  def self.record!(user:, action:, subject: nil, ip: nil, details: {})
    create!(user: user, user_email: user&.email_address.to_s, action: action.to_s,
            subject: subject, subject_label: label_for(subject), ip: ip,
            details: details.compact_blank)
  end

  # A human-readable snapshot of the subject at action time, so the row
  # still reads after the subject is gone.
  def self.label_for(subject)
    return nil if subject.nil?

    %i[email email_address name cidr].each do |attribute|
      value = subject.try(attribute)
      return value if value.present?
    end
    "#{subject.class.name} ##{subject.id}"
  end
end
