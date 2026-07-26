class EmailMessagesController < ApplicationController
  def show
    @email_account = EmailAccount.find(params[:email_account_id])
    @mailbox = @email_account.mailboxes.find(params[:mailbox_id])
    @email_message = @mailbox.email_messages.find(params[:id])
    @email_message.mark_seen!
  end
end
