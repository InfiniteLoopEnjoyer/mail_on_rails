# Smoke-test SMTP/IMAP login against a deployed mail_on_rails server, the same
# way a real mail client would (TCP from outside, TLS, AUTH/LOGIN).
#
#   bin/rails mail_on_rails:login_check EMAIL=alice@example.com PASSWORD=secret
#
# Env:
#   EMAIL, PASSWORD  - mail account credentials (required)
#   HOST             - server to test (required, e.g. mail.example.com)
#   SMTP_PORT, SMTPS_PORT, IMAP_PORT, IMAPS_PORT
#                    - port overrides (defaults: 587, 465, 143, 993; use the
#                      1xxx ports with HOST=localhost against a dev server)
#   VERIFY=0         - skip TLS certificate verification (self-signed certs)
#
# No mail is sent and nothing is modified: SMTP stops after AUTH succeeds,
# IMAP does a read-only EXAMINE of INBOX.
namespace :mail_on_rails do
  desc "Log in to the deployed SMTP/IMAP servers and report whether each port works"
  task :login_check do
    require "net/smtp"
    require "net/imap"
    require "rainbow"

    host = ENV["HOST"] or abort "Usage: bin/rails mail_on_rails:login_check HOST=mail.example.com EMAIL=... PASSWORD=..."
    email = ENV["EMAIL"] or abort "Usage: bin/rails mail_on_rails:login_check HOST=mail.example.com EMAIL=... PASSWORD=..."
    password = ENV["PASSWORD"] or abort "PASSWORD is required"
    verify = ENV["VERIFY"] != "0"
    verify_mode = verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

    smtp_check = lambda do |port, tls:|
      smtp = Net::SMTP.new(host, port,
        tls: tls, starttls: (tls ? false : :always), tls_verify: verify)
      smtp.open_timeout = smtp.read_timeout = 15
      smtp.start("login-check.local", user: email, secret: password, authtype: :plain)
      "authenticated"
    ensure
      smtp.finish if smtp&.started?
    end

    imap_check = lambda do |port, tls:|
      ssl = tls ? { verify_mode: verify_mode } : false
      imap = Net::IMAP.new(host, port: port, ssl: ssl, open_timeout: 15)
      begin
        imap.starttls(verify_mode: verify_mode) unless tls
        imap.login(email, password)
        imap.examine("INBOX")
        exists = imap.responses("EXISTS", &:last)
        "authenticated, INBOX has #{exists} message#{"s" unless exists == 1}"
      ensure
        imap.logout rescue nil
        imap.disconnect rescue nil
      end
    end

    checks = {
      "SMTP  #{host}:#{ENV.fetch("SMTP_PORT", 587)} (STARTTLS)" =>
        -> { smtp_check.call(Integer(ENV.fetch("SMTP_PORT", 587)), tls: false) },
      "SMTPS #{host}:#{ENV.fetch("SMTPS_PORT", 465)} (implicit TLS)" =>
        -> { smtp_check.call(Integer(ENV.fetch("SMTPS_PORT", 465)), tls: true) },
      "IMAP  #{host}:#{ENV.fetch("IMAP_PORT", 143)} (STARTTLS)" =>
        -> { imap_check.call(Integer(ENV.fetch("IMAP_PORT", 143)), tls: false) },
      "IMAPS #{host}:#{ENV.fetch("IMAPS_PORT", 993)} (implicit TLS)" =>
        -> { imap_check.call(Integer(ENV.fetch("IMAPS_PORT", 993)), tls: true) }
    }

    puts "Checking mail login for #{Rainbow(email).cyan} on #{Rainbow(host).cyan}" \
         "#{Rainbow(" (TLS verification off)").yellow unless verify}\n\n"
    failures = 0

    checks.each do |label, check|
      begin
        detail = check.call
        puts "  #{Rainbow("PASS").green.bold}  #{label} - #{detail}"
      rescue OpenSSL::SSL::SSLError => e
        failures += 1
        puts "  #{Rainbow("FAIL").red.bold}  #{label} - TLS error: #{e.message}"
        puts Rainbow("        (self-signed cert? retry with VERIFY=0)").yellow if e.message.match?(/verify/i)
      rescue StandardError => e
        failures += 1
        puts "  #{Rainbow("FAIL").red.bold}  #{label} - #{e.class}: #{e.message}"
      end
    end

    puts
    if failures.zero?
      puts Rainbow("All #{checks.size} checks passed.").green.bold
    else
      abort Rainbow("#{failures} of #{checks.size} checks failed.").red.bold
    end
  end
end
