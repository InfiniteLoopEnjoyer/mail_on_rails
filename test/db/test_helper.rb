# frozen_string_literal: true

# Harness for the DB-backed suite: the adapter-portability tests for the
# Active Record side of the gem (the migrations, the models, the store
# plumbing). Unlike the protocol suites this DOES boot Active Record - but
# still no Rails application - so it too runs in its own clean ruby
# process (rake test:db). The heavy lifting is the gem's own reusable
# harness, MailOnRails::Testing::Database (the protocol gems' store suites
# use the same one): DATABASE_URL picks the adapter, without one the suite
# runs against a file-backed SQLite database under tmp/.
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

# An empty DATABASE_URL (a CI matrix leg without one) must read as
# "unset": Active Record refuses an empty URL the moment Base loads.
ENV.delete("DATABASE_URL") if ENV["DATABASE_URL"].to_s.strip.empty?

require "minitest/autorun"
require "mail_on_rails/testing/database"

# Minimal stand-in for the Rails-style `test "..."` declaration so suites
# read like Rails ones without pulling in ActiveSupport::TestCase.
module Minitest
  class Test
    def self.test(name, &block)
      define_method("test_#{name.gsub(/\W+/, '_')}", &block)
    end

    def assert_not(object, message = nil)
      refute object, message
    end
  end
end

MailOnRails::Testing::Database.setup!(sqlite_path: File.expand_path("../../tmp/db_suite.sqlite3", __dir__))

# The suite's historical spelling of the harness.
module DbSuite
  TABLES_CHILD_FIRST = MailOnRails::Testing::Database.tables
  TestCase = MailOnRails::Testing::Database::TestCase

  def self.postgres? = MailOnRails::Testing::Database.postgres?
  def self.mysql?    = MailOnRails::Testing::Database.mysql?
  def self.sqlite?   = MailOnRails::Testing::Database.sqlite?
  def self.reset_schema! = MailOnRails::Testing::Database.reset_schema!
end
