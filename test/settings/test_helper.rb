# frozen_string_literal: true

# Standalone harness: nothing from Rails or the host app is loaded here.
# The settings schema must resolve correctly in exactly this situation -
# a process with no database and no initializer.
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

require "minitest/autorun"
require "mail_on_rails/settings"

# Minimal stand-in for the Rails-style `test "..."` declaration so suites
# read like Rails ones without pulling in ActiveSupport.
module Minitest
  class Test
    def self.test(name, &block)
      define_method("test_#{name.gsub(/\W+/, '_')}", &block)
    end

    # ActiveSupport::TestCase spelling.
    def assert_not(object, message = nil)
      refute object, message
    end
  end
end

# Runs +block+ with the given ENV values, restoring the previous state -
# including "was unset" - afterwards.
def with_env(pairs)
  saved = pairs.keys.to_h { |k| [ k, ENV.key?(k) ? ENV[k] : :unset ] }
  pairs.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  yield
ensure
  saved.each { |k, v| v == :unset ? ENV.delete(k) : ENV[k] = v }
end
