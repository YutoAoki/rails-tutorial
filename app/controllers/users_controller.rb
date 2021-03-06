class UsersController < ApplicationController
  before_action :logged_in_user, only: [:edit, :update, :index, :show, :following, :followers]
  before_action :correct_user, only: [:edit, :update]

  def index
    # @users = User.paginate(page: params[:page])
    #リスト11.40で下記に書き換え。
    @users = User.where(activated: true).paginate(page: params[:page])
  end

  def new
    @user = User.new
  end

  def show
    @user = User.find(params[:id])
    @microposts = @user.microposts.paginate(page: params[:page])
    # リスト13.23で上記を追加
    redirect_to root_url and return unless @user.activated?
    # debugger
  end

  def create
    @user = User.new(user_params)
    if @user.save
      #リスト11.36で下記機能をユーザーモデル内のメソッドに置き換え。
      # UserMailer.account_activation(@user).deliver_now
      @user.send_activation_email
      flash[:info] = "Please check your email activate your account."
      redirect_to root_url

      #ここはユーザーの有効化の際に消す。
      # log_in(@user)
      # flash[:success] = "Welcome to the Sample App!!"
      # redirect_to @user
    else
      render 'new'
    end
  end

  def edit
    @user = User.find(params[:id])
  end

  def update
    @user = User.find(params[:id])
    if @user.update_attributes(user_params)
      redirect_to @user
    else
      render 'edit'
    end
  end

  def destroy
    User.find(params[:id]).destroy
    flash[:success] = "User deleted"
    redirect_to users_path
  end

  def following
    @title = "Following"
    @user = User.find(params[:id])
    @users = @user.following.paginate(page: params[:page])
    render 'show_follow'
  end

  def followers
    @title = "Followers"
    @user = User.find(params[:id])
    @users = @user.followers.paginate(page: params[:page])
    render 'show_follow'
  end



  private
    def user_params
      params.require(:user).permit(:name, :email, :password, :password_confirmation)
    end

# 13.33でapplication_controllerに移設
    # def logged_in_user
    #   unless logged_in?
    #     store_location
    #     flash[:danger] = "Please log in"
    #     redirect_to login_url
    #   end
    # end

    def correct_user
      @user = User.find(params[:id])
      redirect_to(root_path) unless current_user?(@user)
    end

end
