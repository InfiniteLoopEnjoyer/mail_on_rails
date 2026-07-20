class EmailAccountsController < ApplicationController
  before_action :set_email_account, only: %i[show edit update destroy]

  def index
    @email_accounts = EmailAccount.order(:email).includes(:mailboxes)
  end

  def show
    @mailboxes = @email_account.mailboxes.sort_by do |mailbox|
      [ EmailAccount::DEFAULT_MAILBOXES.index(mailbox.name) || EmailAccount::DEFAULT_MAILBOXES.length, mailbox.name ]
    end
  end

  def new
    @email_account = EmailAccount.new
  end

  def create
    @email_account = EmailAccount.new(email_account_params)
    if @email_account.save
      redirect_to @email_account, notice: "Account #{@email_account.email} created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    if @email_account.update(email_account_params)
      redirect_to @email_account, notice: "Account updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    @email_account.destroy!
    redirect_to root_path, notice: "Account #{@email_account.email} deleted.", status: :see_other
  end

  private

  def set_email_account
    @email_account = EmailAccount.find(params[:id])
  end

  # A blank password on edit means "keep the current one".
  def email_account_params
    params.expect(email_account: [ :email, :name, :password ]).tap do |permitted|
      permitted.delete(:password) if permitted[:password].blank?
    end
  end
end
