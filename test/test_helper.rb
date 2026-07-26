ENV["RAILS_ENV"] ||= "test"
# ClamavScanner defaults to the clamav accessory's docker address when the
# env is unset; pin it off so un-stubbed code paths never open a socket.
# Tests exercising the scanner stub it (ClamavStubHelper) or set their own
# address (clamav_scanner_test.rb).
ENV["SMTP_CLAMAV_ADDR"] ||= ""
require_relative "../config/environment"
require "rails/test_help"
require_relative "test_helpers/session_test_helper"

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Add more helper methods to be used by all tests here...
  end
end
