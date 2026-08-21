# frozen_string_literal: true

require "puma/plugin"

# Runs the installed mail_on_rails servers (SMTP and/or IMAP, whichever
# protocol gems are in the bundle) inside the Puma process, started once
# the Rails app has booted (registered from config/puma.rb via
# `plugin :mail_on_rails`). Wired up by MailOnRails::Runtime: start after
# boot, wait for the listeners to bind (host apps gate /up on
# MailOnRails.ready?), and drain gracefully on Puma stop/restart.
#
# Which protocols run here is MailOnRails::Runtime.in_process_protocols:
# `config.mail_on_rails.protocols`, else MAIL_ON_RAILS_SERVERS
# ("smtp,imap" / "smtp" / "imap" / "0"), else every installed protocol in
# development and none elsewhere. With nothing to serve the plugin is a
# no-op, so it is safe to load unconditionally - the same config/puma.rb
# then serves a web-only process (listeners in other containers) and the
# all-in-one process.
Puma::Plugin.create do
  def start(launcher)
    require "mail_on_rails"
    @protocols = MailOnRails::Runtime.in_process_protocols
    if @protocols.empty?
      launcher.log_writer.log("[mail_on_rails] no mail listeners in this process " \
                              "(MAIL_ON_RAILS_SERVERS / config.mail_on_rails.protocols)")
      return
    end

    if launcher.options[:workers].to_i > 1
      raise "the :mail_on_rails plugin is incompatible with WEB_CONCURRENCY > 1 - " \
            "the mail listeners must live in exactly one process (run them in their own " \
            "process with bin/mail_server instead, or set MAIL_ON_RAILS_SERVERS=0 here)"
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
    MailOnRails.start_servers(protocols: @protocols)
    MailOnRails.wait_ready!
  end

  def stop_servers
    return unless @started

    @started = false
    MailOnRails.stop_servers
  end
end
