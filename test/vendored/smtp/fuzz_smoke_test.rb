# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/fuzz/config"
require "mail_on_rails/fuzz/mutator"
require "mail_on_rails/fuzz/runner"
require "mail_on_rails/fuzz/smtp"

# CI smoke: a handful of fuzz rounds must pass the security oracles. Deep
# runs use bin/rails fuzz:smtp with a higher FUZZ_ROUNDS.
class SmtpFuzzSmokeTest < Minitest::Test
  def test_stateful_fuzz_rounds_pass_security_oracles
    fuzzer = MailOnRails::Fuzz::Smtp.new(rounds: 15, seed: 0xF00D)
    failures = fuzzer.run
    assert_empty failures, failures.map { |f| "round #{f.round} #{f.profile}: #{f.message}" }.join("\n")
  end
end
