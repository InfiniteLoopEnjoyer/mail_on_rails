# Compose and send mail from the web UI. The From select is deliberately
# unscoped - any signed-in user (they are all admins here) can send as any
# hosted account. Routing/queueing lives in ComposedEmail#deliver.
class EmailsController < ApplicationController
  def new
    @composed_email = ComposedEmail.new(email_account_id: params[:from])
    load_accounts
  end

  def create
    @composed_email = ComposedEmail.new(composed_email_params)
    if @composed_email.deliver
      account = @composed_email.account
      sent = account.find_mailbox("Sent")
      destination = sent ? email_account_mailbox_path(account, sent) : email_account_path(account)
      redirect_to destination, notice: "Email sent."
    else
      load_accounts
      render :new, status: :unprocessable_entity
    end
  end

  private

  def load_accounts
    @email_accounts = EmailAccount.order(:email)
  end

  def composed_email_params
    params.expect(composed_email: [ :email_account_id, :to, :subject, :body ])
  end
end
