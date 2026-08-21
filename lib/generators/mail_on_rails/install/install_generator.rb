# frozen_string_literal: true

module MailOnRails
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      def copy_files
        template "bin/mail_server"
        chmod "bin/mail_server", 0o755 & ~File.umask, verbose: false
        template "config/initializers/mail_on_rails.rb"
      end

      def route_inbound_mail
        mailbox_path = Pathname(destination_root).join("app/mailboxes/application_mailbox.rb")
        if mailbox_path.exist?
          inject_into_file mailbox_path, "  routing all: :\"mail_on_rails/mailroom\"\n",
                           after: /class ApplicationMailbox < ActionMailbox::Base\n/, verbose: true
        else
          say "Add `routing all: :\"mail_on_rails/mailroom\"` to your ApplicationMailbox", :yellow
        end
      end

      # Inbound mail arrives in-process (the SMTP edge hands sealed messages
      # to Action Mailbox directly), so no HTTP ingress should exist. An
      # open ingress would accept unsealed mail, which the mailroom drops -
      # but pinning the routes closed keeps the surface from existing at
      # all. Drawn before the framework's own routes, this match answers
      # the same 404 an unknown path would.
      def pin_action_mailbox_ingress
        route <<~RUBY
          # mail_on_rails ingests inbound mail in-process, not over HTTP; pin
          # Action Mailbox's ingress routes closed (remove only if you enable a
          # real ingress - the mailroom still requires sealed messages).
          match "rails/action_mailbox/*path", via: :all,
            to: proc { [ 404, { "Content-Type" => "text/plain" }, [ "Not Found\\n" ] ] }
        RUBY
      end

      def show_post_install
        say <<~MSG, :green

          mail_on_rails installed. Next steps:
            1. bin/rails db:migrate
            2. Mount the engine for MTA-STS:  mount MailOnRails::Engine => "/"
            3. Serve mail in-process:         plugin :mail_on_rails  (config/puma.rb, WEB_CONCURRENCY=1)
               ...or standalone:              bin/mail_server
        MSG
      end
    end
  end
end
