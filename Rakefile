# frozen_string_literal: true

require "bundler/gem_tasks"

# The protocol suites (test/imap, test/smtp) are Rails-free and run in a
# clean ruby subprocess: their test_helper defines a minimal `test "..."`
# shim on Minitest::Test that would collide with ActiveSupport::TestCase
# if loaded into a Rails test process.
namespace :test do
  {
    imap: "test/imap",
    smtp: "test/smtp",
    settings: "test/settings",
    dnssec: "test/dnssec"
  }.each do |task_name, dir|
    desc "Run the #{task_name.to_s.upcase} protocol suite"
    task task_name do
      command = [
        RbConfig.ruby, "-Ilib", "-I#{dir}",
        "-e", %(Dir.glob("#{dir}/**/*_test.rb").sort.each { |f| require File.expand_path(f) })
      ]
      system(*command, exception: true)
    end
  end

  desc "Run the DB-backed model/store suite (adapter from DATABASE_URL; defaults to SQLite)"
  task :db do
    command = [
      RbConfig.ruby, "-Ilib", "-Itest/db",
      "-e", %(Dir.glob("test/db/**/*_test.rb").sort.each { |f| require File.expand_path(f) })
    ]
    system(*command, exception: true)
  end
end

desc "Run the protocol suites and the DB suite"
task test: [ "test:settings", "test:imap", "test:smtp", "test:dnssec", "test:db" ]

task default: :test
