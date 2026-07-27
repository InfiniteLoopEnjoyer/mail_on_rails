# A registered passkey (platform authenticator or security key). Only the
# public key is stored; the private half never leaves the authenticator.
# external_id is the authenticator's credential id (base64url), the handle
# both ceremonies look credentials up by.
class WebauthnCredential < ApplicationRecord
  belongs_to :user

  validates :external_id, presence: true, uniqueness: true
  validates :public_key, :nickname, presence: true
end
