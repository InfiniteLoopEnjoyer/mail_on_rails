# The audit trail viewer (/audit): every admin action recorded by the
# Auditing concern, newest first. Read-only - the rows themselves are
# immutable (AuditEvent#readonly?).
class AuditEventsController < ApplicationController
  PER_PAGE = 50

  def index
    scope = AuditEvent.newest_first
    @count = scope.count
    @pages = [ @count.fdiv(PER_PAGE).ceil, 1 ].max
    @page = params[:page].to_i.clamp(1, @pages)
    @audit_events = scope.offset((@page - 1) * PER_PAGE).limit(PER_PAGE)
  end
end
