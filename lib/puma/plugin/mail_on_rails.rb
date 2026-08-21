# frozen_string_literal: true

require "puma/plugin"

# Runs the mail_on_rails IMAP and SMTP servers inside the Puma process,
# started once the Rails app has booted (registered from config/puma.rb via
# `plugin :mail_on_rails`). Wired up by MailOnRails::Runtime: start after
# boot, wait for the listeners to bind (host apps gate /up on
# MailOnRails.ready?), and drain gracefully on Puma stop/restart.
Puma::Plugin.create do
  def start(launcher)
    if launcher.options[:workers].to_i > 1
      raise "the :mail_on_rails plugin is incompatible with WEB_CONCURRENCY > 1 - " \
            "the mail listeners must live in exactly one process"
    end

    events = launcher.events
    hook = events.respond_to?(:after_booted) ? :after_booted : :on_booted
    events.public_send(hook) { boot_servers }
    stop_hook = events.respond_to?(:after_stopped) ? :after_stopped : :on_stopped
    events.public_send(stop_hook) { stop_servers }
    restart_hook = events.respond_to?(:before_restart) ? :before_restart : :on_restart
    events.public_send(restart_hook) { stop_servers }
  end

  private

  def boot_servers
    return if @started

    @started = true
    require "mail_on_rails"
    MailOnRails.start_servers
    MailOnRails.wait_ready!
  end

  def stop_servers
    return unless @started

    @started = false
    MailOnRails.stop_servers
  end
end
