class EmailMessagesController < ApplicationController
  before_action :set_email_message

  def show
    # Turbo prefetches links on hover; only an actual visit marks the message
    # read. A click served from the prefetch cache never re-requests, so the
    # page POSTs to mark_read instead (see the mark-read Stimulus controller).
    @email_message.mark_seen! unless prefetch_request?
    # Replying to your own unsent draft is nonsense; that page offers to
    # carry on writing it instead (see the view).
    @draft = EmailDraft.reply_to(@email_message, account: @email_account) unless @email_message.draft?
  end

  def mark_read
    @email_message.mark_seen!
    head :no_content
  end

  private

  def set_email_message
    @email_account = EmailAccount.find(params[:email_account_id])
    @mailbox = @email_account.mailboxes.find(params[:mailbox_id])
    @email_message = @mailbox.email_messages.find(params[:id])
  end

  def prefetch_request?
    [ request.headers["X-Sec-Purpose"], request.headers["Sec-Purpose"] ].any? { |h| h.to_s.include?("prefetch") }
  end
end
