class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
         :confirmable, :lockable

  def serializable_hash(options = nil) 
    super(options).merge(encrypted_password: encrypted_password, reset_password_token: reset_password_token, confirmed_at: confirmed_at) # you can keep adding attributes here that you wish to expose
  end
end
