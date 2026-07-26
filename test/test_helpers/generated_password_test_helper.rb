# Pulls the one-time generated password out of the last response's reveal
# markup (<code data-clipboard-target="source">...</code>).
module GeneratedPasswordTestHelper
  def extract_generated_password
    response.body[/<code[^>]*data-clipboard-target="source"[^>]*>([^<]+)<\/code>/, 1].tap do |plaintext|
      assert plaintext.present?, "expected a generated password in the response body"
    end
  end
end

ActiveSupport.on_load(:action_dispatch_integration_test) do
  include GeneratedPasswordTestHelper
end
