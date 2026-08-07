# frozen_string_literal: true

# The vendored protocol-server suites (test/vendored/*) are Rails-free and
# run in a clean ruby subprocess: their test_helper defines a minimal
# `test "..."` shim on Minitest::Test that would collide with
# ActiveSupport::TestCase if loaded into the main suite's process.
namespace :test do
  {
    imap_server: "test/vendored/imap",
    smtp_server: "test/vendored/smtp"
  }.each do |task_name, dir|
    desc "Run the vendored #{task_name.to_s.sub("_server", "").upcase} server suite"
    task task_name do
      next unless Dir.exist?(Rails.root.join(dir))

      command = [
        RbConfig.ruby, "-Ilib", "-I#{dir}",
        "-e", %(Dir.glob("#{dir}/**/*_test.rb").sort.each { |f| require File.expand_path(f) })
      ]
      system(*command, exception: true)
    end
  end
end
