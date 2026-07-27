class AddTwoFactor < ActiveRecord::Migration[8.1]
  def change
    change_table :users, bulk: true do |t|
      # Stable user handle sent to authenticators (WebAuthn.generate_user_id,
      # assigned when the first passkey is registered).
      t.string :webauthn_id
      # TOTP fallback: encrypted shared secret, plus the last accepted
      # timestep so a code can't be replayed inside its validity window.
      t.string :otp_secret
      t.bigint :otp_last_used_at
    end

    create_table :webauthn_credentials do |t|
      t.references :user, null: false, foreign_key: true
      t.string :external_id, null: false, index: { unique: true }
      t.string :public_key, null: false
      t.bigint :sign_count, null: false, default: 0
      t.string :nickname, null: false
      t.timestamps
    end
  end
end
