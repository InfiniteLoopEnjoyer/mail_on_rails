# frozen_string_literal: true

module MailOnRails
  module Fuzz
    Failure = Data.define(:round, :profile, :message, :detail)

    # Drives N fuzz rounds, collects failures, and prints a summary. Subclasses
    # implement #run_round and inherit reporting.
    class Runner
      attr_reader :config, :rng, :mutator, :failures

      def initialize(config: Config, seed: config.seed, rounds: config.rounds)
        @config = config
        @rounds = rounds
        @seed = seed
        @rng = Random.new(seed)
        @mutator = Mutator.new(@rng)
        @failures = []
      end

      def run!
        failures = run
        exit(failures.empty? ? 0 : 1)
      end

      def run
        @rounds.times { |i| run_round(i) }
        report
        @failures
      end

      def fail(round, profile, message, detail = nil)
        @failures << Failure.new(round: round, profile: profile, message: message, detail: detail)
        warn "[fuzz] round #{round} (#{profile}): #{message}"
        warn "  #{detail}" if detail && config.verbose
      end

      def report
        puts "\n== fuzz summary =="
        puts "rounds: #{@rounds}"
        puts "failures: #{@failures.size}"
        @failures.first(10).each do |f|
          puts "  round #{f.round} #{f.profile}: #{f.message}"
        end
        puts "(seed #{@seed} — replay with FUZZ_SEED=#{@seed})"
      end

      private

      def pick(array) = array.sample(random: @rng)
    end
  end
end
