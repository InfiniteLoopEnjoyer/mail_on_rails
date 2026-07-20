class UsersController < ApplicationController
  before_action :set_user, only: %i[edit update destroy]

  def index
    @users = User.order(:email_address)
  end

  def new
    @user = User.new
  end

  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to users_path, notice: "User #{@user.email_address} created."
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

  private

  def set_user
    @user = User.find(params[:id])
  end

  # A blank password on edit means "keep the current one".
  def user_params
    params.expect(user: [ :email_address, :password ]).tap do |permitted|
      permitted.delete(:password) if permitted[:password].blank?
    end
  end
end
