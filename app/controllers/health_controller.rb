# The /up endpoint kamal health-checks during deploys. On top of Rails'
# stock "booted without exceptions" check, this reports down (500) until
# the in-process mail servers have bound their listeners - the whole point
# of the unified deploy is that a container reporting healthy can serve
# every protocol, not just HTTP. Gated on MAIL_ON_RAILS_SERVERS (the
# production web role's setting) so a dev/test boot without the Puma
# plugin still answers 200.
class HealthController < Rails::HealthController
  before_action :require_mail_listeners

  private

  def require_mail_listeners
    return unless ENV["MAIL_ON_RAILS_SERVERS"] == "true"

    require "mail_on_rails/boot"
    render_down unless MailOnRails::Boot.ready?
  end
end
