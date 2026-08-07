require_relative "boot"

require "rails/all"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module MailOnRails
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1

    # Please, add to the `ignore` list any other `lib` subdirectories that do
    # not contain `.rb` files, or that should not be reloaded or eager loaded.
    # Common ones are `templates`, `generators`, or `middleware`, for example.
    # mail_on_rails (in-process SMTP/IMAP servers) and puma (Puma plugin) are
    # required explicitly, never autoloaded: the server threads hold
    # references to these classes for the process lifetime, so they must not
    # be reloaded in development.
    config.autoload_lib(ignore: %w[assets tasks mail_on_rails puma])

    # Referrer-Policy: tighter than Rails' strict-origin-when-cross-origin
    # default - an admin UI's paths leak nothing to any external site. Links
    # inside displayed mail already carry rel=noreferrer from the sanitizer;
    # this covers the app chrome.
    #
    # Permissions-Policy: deny browser features this UI never uses. Set as a
    # plain header because Rails' permissions_policy DSL still emits the
    # obsolete Feature-Policy name (actionpack constants), which browsers
    # ignore. WebAuthn's publickey-credentials-get is deliberately absent
    # (stays at its browser default); usb blocks WebUSB only, not security
    # keys.
    config.action_dispatch.default_headers = config.action_dispatch.default_headers.merge(
      "Referrer-Policy" => "same-origin",
      "Permissions-Policy" => "camera=(), microphone=(), geolocation=(), usb=(), payment=()"
    )

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")
  end
end
