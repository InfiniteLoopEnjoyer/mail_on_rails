# frozen_string_literal: true

require "bundler/gem_tasks"

# The Rails-free suites run in a clean ruby subprocess: their test_helper
# defines a minimal `test "..."` shim on Minitest::Test that would collide
# with ActiveSupport::TestCase if loaded into a Rails test process. Shared
# fakes (DNS, resolver, clamd, rspamd) live in test/support.
#
#   settings     the settings schema
#   netserv      listener scaffolding shared by the protocol servers
#                (limits, throttles, denylist, transcript, ops sync)
#   sender_auth  SPF/DKIM/DMARC/ARC primitives and the DNS client
#   lib          other stdlib-only primitives (SCRAM, send quota, clamd
#                client, ingress seal)
#   dnssec       the validating stub resolver
#   imap / smtp  the protocol servers (one-package phase; they move to
#                the mail_on_rails_imap / mail_on_rails_smtp gems)
namespace :test do
  {
    settings: "test/settings",
    netserv: "test/netserv",
    sender_auth: "test/sender_auth",
    lib: "test/lib",
    dnssec: "test/dnssec",
    imap: "test/imap",
    smtp: "test/smtp"
  }.each do |task_name, dir|
    desc "Run the #{task_name} suite (#{dir}; Rails-free)"
    task task_name do
      next unless Dir.exist?(dir)

      command = [
        RbConfig.ruby, "-Ilib", "-Itest/support", "-I#{dir}",
        "-e", %(Dir.glob("#{dir}/**/*_test.rb").sort.each { |f| require File.expand_path(f) })
      ]
      system(*command, exception: true)
    end
  end

  desc "Run the DB-backed model/store suite (adapter from DATABASE_URL; defaults to SQLite)"
  task :db do
    command = [
      RbConfig.ruby, "-Ilib", "-Itest/support", "-Itest/db",
      "-e", %(Dir.glob("test/db/**/*_test.rb").sort.each { |f| require File.expand_path(f) })
    ]
    system(*command, exception: true)
  end
end

desc "Run every suite"
task test: [ "test:settings", "test:netserv", "test:sender_auth", "test:lib", "test:dnssec",
             "test:imap", "test:smtp", "test:db" ]

task default: :test
