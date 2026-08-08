# frozen_string_literal: true

module MailOnRails
  module Fuzz
    # Runtime knobs for the protocol fuzz harnesses. All values are read from
    # the environment so deep local runs need no code changes:
    #
    #   FUZZ_ROUNDS=10000 FUZZ_SEED=42 bin/rails fuzz:smtp
    class Config
      DEFAULT_ROUNDS = 100
      DEFAULT_SEED = 0xFEED_F00D
      DEFAULT_TIMEOUT = 2

      def self.rounds = int("FUZZ_ROUNDS", DEFAULT_ROUNDS, min: 1)
      def self.seed = int("FUZZ_SEED", DEFAULT_SEED)
      def self.timeout = int("FUZZ_TIMEOUT", DEFAULT_TIMEOUT, min: 1)
      def self.verbose = ENV["FUZZ_VERBOSE"] == "1"

      def self.int(name, default, min: nil)
        value = ENV.fetch(name, default).to_i
        value = default if value.zero? && default != 0
        min ? [ value, min ].max : value
      end
    end
  end
end
