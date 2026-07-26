module GeneratedPassword
  extend ActiveSupport::Concern

  class_methods do
    def generate_password
      SecureRandom.base58(36)
    end
  end

  # Rotates the digest and returns the plaintext (never persisted).
  def regenerate_password!
    self.class.generate_password.tap { |plaintext| update!(password: plaintext) }
  end
end
