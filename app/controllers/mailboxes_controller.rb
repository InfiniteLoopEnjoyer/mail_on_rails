class MailboxesController < ApplicationController
  before_action :set_email_account
  before_action :set_mailbox, only: %i[show edit update destroy]

  def show
    @email_messages = @mailbox.email_messages.order(internal_date: :desc, uid: :desc)
  end

  def new
    @mailbox = @email_account.mailboxes.new
  end

  def create
    @mailbox = @email_account.mailboxes.new(mailbox_params)
    if @mailbox.save
      redirect_to email_account_path(@email_account), notice: "Folder #{@mailbox.name} created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    if @mailbox.update(mailbox_params)
      redirect_to email_account_mailbox_path(@email_account, @mailbox), notice: "Folder updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    if @mailbox.destroy
      redirect_to email_account_path(@email_account), notice: "Folder #{@mailbox.name} deleted.", status: :see_other
    else
      redirect_to email_account_mailbox_path(@email_account, @mailbox),
                  alert: @mailbox.errors.full_messages.to_sentence, status: :see_other
    end
  end

  private

  def set_email_account
    @email_account = EmailAccount.find(params[:email_account_id])
  end

  def set_mailbox
    @mailbox = @email_account.mailboxes.find(params[:id])
  end

  def mailbox_params
    params.expect(mailbox: [ :name ])
  end
end
