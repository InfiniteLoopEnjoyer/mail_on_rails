# The write side of the audit log: admin controllers call audit(...) after
# a successful mutation. Best-effort by design - failing to write history
# must never fail the action being recorded (it is logged instead).
module Auditing
  extend ActiveSupport::Concern

  private

  def audit(action, subject = nil, **details)
    AuditEvent.record!(user: Current.user, action: action, subject: subject,
                       ip: request.remote_ip, details: details)
  rescue StandardError => e
    Rails.logger.error "[mail_on_rails] audit write failed (#{action}): #{e.class}: #{e.message}"
  end
end
