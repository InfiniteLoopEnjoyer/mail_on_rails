ENV["BUNDLE_GEMFILE"] ||= File.expand_path("../Gemfile", __dir__)

# The vendored protocol-server suites under test/vendored are Rails-free
# and run in their own process (bin/rails test:imap_server /
# test:smtp_server); their minitest shim must not load into the app suite.
ENV["DEFAULT_TEST_EXCLUDE"] ||= "test/{system,dummy,fixtures,vendored}/**/*_test.rb"

require "bundler/setup" # Set up gems listed in the Gemfile.
require "bootsnap/setup" # Speed up boot time by caching expensive operations.
