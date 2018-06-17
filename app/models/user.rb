class User < ApplicationRecord
  attr_accessor :remember_token, :activation_token, :reset_token
  #データベースに保存したくない値。　＝＝フィールド。
  before_save :downcase_email
  before_create :create_activation_digest
  # before_save {self.email = email.downcase}
  validates :name, presence: true, length: {maximum: 50}
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d-]+)*\.[a-z]+\z/i
  validates :email, presence: true, length: {maximum: 255},
            format: {with: VALID_EMAIL_REGEX},
            uniqueness: {case_sensitive: false}
  validates :password, presence: true, length: {minimum: 6}, allow_nil: true
  has_secure_password
  has_many :microposts, dependent: :destroy
  # validates→ saveを走らせた時にvalidメソッド(valid?)が走る。
  # valid?がtrueにならないとsaveできない。
  # https://qiita.com/kadoppe/items/061d137e6022fa099872
  # allow_nil: true →　オプション　／nilの場合は無視するオプション
  # presence: true→スペースもNG　　　　nil→何も無い状態。
  # validationの代わりに、  if params[:user][:password].nil? → render "edit" これでもOK
  # user edit パスワードが空欄の場合　if params[:user][:password].nil?
  # → nil? == true → params[:user].delete(:password)　→ paramsからpassword自体消す。

  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST:
                              BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end


  def User.new_token
    SecureRandom.urlsafe_base64
  end

  def remember
    self.remember_token = User.new_token
    #self.　→　インスタンスの中のフォールドにアクセスして、User.new_tokenを書き込んでる。
    # （attr_accessorで作成したフィールド）
    update_attribute(:remember_digest, User.digest(remember_token))
    # これは、update_attributeというメソッドを呼び出している。self.(インスタンス変数)に対しても実行可能。
    # :remember_digestはテーブルのカラムの項目。カラムに書き込みに行っている。
  end
  # リメンバーメソッドでやっていること。
  # →remember_token・・・後ほどクッキーに入れる値。
  # remember_tokenはbase64で作成した文字列を代入する。
  # →remember_digest・・・Userテーブルに入れる値。
  # base64で一度作り出した文字列をUser.digestで暗号化している。
  # →クッキーに保存している値は誰でもとりだすことができるので、テーブルに保存している値と
  # 　クッキーの値は違う値を入れておく必要がある。

  # def authenticated?(remember_token)
  #   BCrypt::Password.new(remember_digest).is_password?(remember_token)
  # end

  #11.3で上記を書き換え。
  def authenticated?(attribute, token)
    digest = self.send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end

  def forget
    update_attribute(:remember_digest, nil)
  end

  def activate
    update_attribute(:activated, true)
    update_attribute(:activated_at, Time.zone.now)
  end

  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end

  def create_reset_digest
    self.reset_token = User.new_token
    update_attribute(:reset_digest, User.digest(reset_token))
    update_attribute(:reset_sent_at, Time.zone.now)
  end

  def sent_password_reset_email
    UserMailer.password_reset(self).deliver_now
  end

  def password_reset_expired?
    reset_sent_at < 2.hours.ago
  end

  def feed
    Micropost.where("user_id = ?", id)
  end

  private

    def downcase_email
      self.email = email.downcase
    end

    def create_activation_digest
      self.activation_token = User.new_token
      self.activation_digest = User.digest(activation_token)
    end

end
