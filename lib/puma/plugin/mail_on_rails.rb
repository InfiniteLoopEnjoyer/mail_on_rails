# frozen_string_literal: true

require "puma/plugin"

# Runs the mail_on_rails SMTP/IMAP servers inside the Puma process, started
# once the Rails app has booted (registered from config/puma.rb via
# `plugin :mail_on_rails` - development, or MAIL_ON_RAILS_SERVERS=true elsewhere).
# In the Kamal deploy the listeners run as their own services from the
# sibling mail_on_rails_smtp / mail_on_rails_imap repos instead; both paths
# share the gems' Daemon runtimes (here wired up by MailOnRails::Boot).
Puma::Plugin.create do
  def start(launcher)
    events = launcher.events
    hook = events.respond_to?(:after_booted) ? :after_booted : :on_booted
    events.public_send(hook) { boot_servers }
  end

  private

  def boot_servers
    return if @started

    @started = true
    require_relative "../../mail_on_rails/boot"
    MailOnRails::Boot.start_servers
  end
end
