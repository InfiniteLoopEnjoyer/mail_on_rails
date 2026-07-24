# frozen_string_literal: true

require "puma/plugin"

# Runs the mail_on_rails IMAP server inside the Puma process, started once
# the Rails app has booted (registered from config/puma.rb via
# `plugin :mail_on_rails` - development, or MAIL_ON_RAILS_SERVERS=true elsewhere).
# In the Kamal deploy the IMAP listener runs as its own service from the
# sibling mail_on_rails_imap repo instead; both paths share the gem's Daemon
# runtime (here wired up by MailOnRails::Boot). The SMTP edge is the external
# mail_on_rails_exim service and is never booted here.
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
