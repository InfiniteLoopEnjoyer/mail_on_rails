class UsersController < ApplicationController
  before_action :set_user, only: %i[edit update destroy generate_password]

  def index
    @users = User.order(:email_address)
  end

  def new
    @user = User.new
  end

  def create
    @user = User.new(user_params)
    @user.password = plaintext = User.generate_password
    if @user.save
      flash[:generated_password] = plaintext
      redirect_to edit_user_path(@user), notice: "User #{@user.email_address} created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    if @user.update(user_params)
      redirect_to users_path, notice: "User updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    if @user == Current.user
      redirect_to users_path, alert: "You can't delete the account you're signed in with.", status: :see_other
    else
      @user.destroy!
      redirect_to users_path, notice: "User #{@user.email_address} deleted.", status: :see_other
    end
  end

  def generate_password
    plaintext = @user.regenerate_password!
    @user.sessions.excluding(Current.session).destroy_all
    respond_to do |format|
      format.turbo_stream do
        render turbo_stream: turbo_stream.replace(
          "password-generator",
          partial: "shared/password_generator",
          locals: { url: generate_password_user_path(@user), password: plaintext }
        )
      end
      format.html do
        flash[:generated_password] = plaintext
        redirect_to edit_user_path(@user)
      end
    end
  end

  private

  def set_user
    @user = User.find(params[:id])
  end

  def user_params
    params.expect(user: [ :email_address ])
  end
end
