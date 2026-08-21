# Rails-side seams for the mail_on_rails servers. Protocol behavior is
# declared in the settings schema (MailOnRails::Settings), layered as
# gem default < ENV < the overrides below < settings table - see the gem
# README and docs/settings.md for the full reference. The legacy
# MAIL_ON_RAILS_* / SMTP_* environment variables all still work.

# Typed overrides of any declared setting, validated at boot:
# config.mail_on_rails.setting_overrides = {
#   smtp_max_conn: 200,
#   smtp_rbl_zones: %w[zen.spamhaus.org]
# }

# Which installed protocols run inside the web process (the Puma plugin).
# Protocols are installed by adding the mail_on_rails_smtp / mail_on_rails_imap
# gems. Unset, MAIL_ON_RAILS_SERVERS decides ("smtp,imap", "smtp", "imap",
# "0"); unset too, development runs every installed protocol and other
# environments run none (run them with bin/mail_server instead). An
# explicit [] means "web UI only".
# config.mail_on_rails.protocols = [ :imap, :smtp ]

# Tell the shared brute-force analysis which web logins actually exist:
# config.mail_on_rails.web_login_lookup = ->(name) { User.exists?(email_address: name) }

# Extend the gem's models without reopening classes:
# ActiveSupport.on_load(:mail_on_rails_email_account) do
#   has_many :account_users, dependent: :destroy
# end

# HTML mail rendering is sanitized by the gem's EmailHtmlSanitizer (strict
# allowlist, cid: inlining, remote-image blocking, deceptive-link stamping).
# To change the policy, define your own EmailHtmlSanitizer in app/models -
# it shadows the gem's - keeping the contract documented on that class.
# Always render the result inside a sandboxed iframe.
