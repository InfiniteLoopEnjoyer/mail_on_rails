# Account-wide full-text search: one query across every folder, matched
# against the GIN-indexed tsvector over subject/from/to/body_text
# (EmailMessage.full_text_search), paginated like the mailbox list.
class SearchesController < ApplicationController
  MESSAGES_PER_PAGE = MailboxesController::MESSAGES_PER_PAGE

  def show
    @email_account = EmailAccount.find(params[:email_account_id])
    @query = params[:q].to_s.strip
    scope =
      if @query.empty?
        EmailMessage.none
      else
        EmailMessage.where(mailbox: @email_account.mailboxes)
                    .full_text_search(@query)
                    .includes(:mailbox)
                    .order(internal_date: :desc, uid: :desc)
      end
    @message_count = scope.count
    @pages = [ @message_count.fdiv(MESSAGES_PER_PAGE).ceil, 1 ].max
    @page = params[:page].to_i.clamp(1, @pages)
    @email_messages = scope.offset((@page - 1) * MESSAGES_PER_PAGE).limit(MESSAGES_PER_PAGE)
  end
end
