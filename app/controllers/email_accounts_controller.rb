class EmailAccountsController < ApplicationController
  before_action :set_email_account, only: %i[show edit update destroy generate_password]

  def index
    @email_accounts = EmailAccount.order(:email).includes(:mailboxes)
    @unseen_counts = EmailMessage.joins(:mailbox)
                                 .where.not("flags LIKE ?", "%Seen%")
                                 .group("mailboxes.email_account_id")
                                 .count
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
    @email_account.password = plaintext = EmailAccount.generate_password
    if @email_account.save
      flash[:generated_password] = plaintext
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

  def generate_password
    plaintext = @email_account.regenerate_password!
    respond_to do |format|
      format.turbo_stream do
        render turbo_stream: turbo_stream.replace(
          "password-generator",
          partial: "shared/password_generator",
          locals: { url: generate_password_email_account_path(@email_account), password: plaintext }
        )
      end
      format.html do
        flash[:generated_password] = plaintext
        redirect_to edit_email_account_path(@email_account)
      end
    end
  end

  private

  def set_email_account
    @email_account = EmailAccount.find(params[:id])
  end

  def email_account_params
    params.expect(email_account: [ :email, :name ])
  end
end
