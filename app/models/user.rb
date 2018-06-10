class User < ApplicationRecord
  attr_accessor :remember_token
  #データベースに保存したくない値。　＝＝フィールド。

  before_save {self.email = email.downcase}
  validates :name, presence: true, length: {maximum: 50}
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d-]+)*\.[a-z]+\z/i
  validates :email, presence: true, length: {maximum: 255},
            format: {with: VALID_EMAIL_REGEX},
            uniqueness: {case_sensitive: false}
  validates :password, presence: true, length: {minimum: 6}, allow_nil: true
  has_secure_password

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

  def authenticated?(remember_token)
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end

  def forget
    update_attribute(:remember_digest, nil)
  end
end
