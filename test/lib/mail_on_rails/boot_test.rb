require "test_helper"
require "mail_on_rails/boot"

# The production TLS guard: require_explicit_tls! (which start_servers
# runs before binding anything when Rails.env.production?) must refuse a
# boot without explicit cert material, per protocol - the self-signed
# fallback is development-only.
class BootTest < ActiveSupport::TestCase
  TLS_ENV = %w[MAIL_ON_RAILS_TLS_CERT MAIL_ON_RAILS_TLS_KEY SMTP_TLS_CERT SMTP_TLS_KEY].freeze

  def with_tls_env(values)
    previous = TLS_ENV.index_with { |name| ENV[name] }
    TLS_ENV.each { |name| values[name] ? ENV[name] = values[name] : ENV.delete(name) }
    yield
  ensure
    previous.each { |name, value| value ? ENV[name] = value : ENV.delete(name) }
  end

  test "a boot without explicit TLS material raises, naming every missing pair" do
    with_tls_env({}) do
      error = assert_raises(RuntimeError) { MailOnRails::Boot.require_explicit_tls!([ :imap, :smtp ]) }
      assert_match(/MAIL_ON_RAILS_TLS_CERT/, error.message)
      assert_match(/SMTP_TLS_CERT/, error.message)
    end
  end

  test "the guard is per protocol" do
    with_tls_env("MAIL_ON_RAILS_TLS_CERT" => "/x/cert.pem", "MAIL_ON_RAILS_TLS_KEY" => "/x/key.pem") do
      # Only the SMTP pair is missing, so only it is named.
      error = assert_raises(RuntimeError) { MailOnRails::Boot.require_explicit_tls!([ :imap, :smtp ]) }
      assert_match(/SMTP_TLS_CERT/, error.message)
      assert_no_match(/MAIL_ON_RAILS_TLS_CERT/, error.message)

      # An IMAP-only boot is satisfied by the IMAP pair alone.
      assert_nothing_raised { MailOnRails::Boot.require_explicit_tls!([ :imap ]) }
    end
  end
end
