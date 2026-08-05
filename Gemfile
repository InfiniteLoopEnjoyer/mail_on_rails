source "https://rubygems.org"

# Bundle edge Rails instead: gem "rails", github: "rails/rails", branch: "main"
gem "rails"

# The modern asset pipeline for Rails [https://github.com/rails/propshaft]
gem "propshaft"
# Use PostgreSQL as the database for Active Record
gem "pg"
# Use the Puma web server [https://github.com/puma/puma]
gem "puma"
# Use JavaScript with ESM import maps [https://github.com/rails/importmap-rails]
gem "importmap-rails"
# Hotwire's SPA-like page accelerator [https://turbo.hotwired.dev]
gem "turbo-rails"
# Hotwire's modest JavaScript framework [https://stimulus.hotwired.dev]
gem "stimulus-rails"

# Use Active Model has_secure_password [https://guides.rubyonrails.org/active_model_basics.html#securepassword]
gem "bcrypt"

# Windows does not include zoneinfo files, so bundle the tzinfo-data gem
gem "tzinfo-data", platforms: %i[ windows jruby ]

# Use the database-backed adapters for Rails.cache, Active Job, and Action Cable
gem "solid_cache"
gem "solid_queue"
gem "solid_cable"

# Reduces boot times through caching; required in config/boot.rb
gem "bootsnap", require: false

# Deploy this application anywhere as a Docker container [https://kamal-deploy.org]
gem "kamal", require: false

# Add HTTP asset caching/compression and X-Sendfile acceleration to Puma [https://github.com/basecamp/thruster/]
gem "thruster", require: false

# Colored terminal output for rake tasks [https://github.com/ku1ik/rainbow]
gem "rainbow", require: false

# DKIM signing for outbound mail (RFC 6376) [https://github.com/jhawthorn/dkim]
gem "dkim"

# Two-factor auth: WebAuthn/passkeys as the primary second factor
# [https://github.com/cedarcode/webauthn-ruby], TOTP authenticator apps as
# the fallback (rotp), with rqrcode rendering the enrollment QR code.
gem "webauthn"
gem "rotp"
gem "rqrcode"

# DMARC aggregate reports arrive as .zip attachments (RFC 7489); gzip and
# plain XML are handled with the stdlib. See DmarcReportParser.
gem "rubyzip", require: "zip"

# Cloudflare API client, used by CloudflareDns/DnsPublisher to publish
# DNS records for hosted domains [https://github.com/socketry/cloudflare]
gem "cloudflare"

group :development, :test do
  # See https://guides.rubyonrails.org/debugging_rails_applications.html#debugging-with-the-debug-gem
  gem "debug", platforms: %i[ mri windows ], require: "debug/prelude"

  # Audits gems for known security defects (use config/bundler-audit.yml to ignore issues)
  gem "bundler-audit", require: false

  # Static analysis for security vulnerabilities [https://brakemanscanner.org/]
  gem "brakeman", require: false

  # Omakase Ruby styling [https://github.com/rails/rubocop-rails-omakase/]
  gem "rubocop-rails-omakase", require: false
end

group :development do
  # Use console on exceptions pages [https://github.com/rails/web-console]
  gem "web-console"
end

group :test do
  # Use system testing [https://guides.rubyonrails.org/testing.html#system-testing]
  gem "capybara"
  gem "selenium-webdriver"
end

gem "tailwindcss-rails"
gem "slim"

# Active Storage variants (attachment thumbnails) [https://guides.rubyonrails.org/active_storage_overview.html#transforming-images]
gem "image_processing"

gem "requestjs-rails"
gem "ruby-vips"
