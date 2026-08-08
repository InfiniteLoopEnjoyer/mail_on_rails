# frozen_string_literal: true

namespace :fuzz do
  {
    smtp: "lib/mail_on_rails/fuzz/smtp_runner.rb",
    imap: "lib/mail_on_rails/fuzz/imap_runner.rb"
  }.each do |name, script|
    desc "Stateful #{name.upcase} fuzz harness (FUZZ_ROUNDS, FUZZ_SEED, FUZZ_TIMEOUT, FUZZ_VERBOSE)"
    task name do
      system(RbConfig.ruby, "-Ilib", script, exception: true)
    end
  end
end
