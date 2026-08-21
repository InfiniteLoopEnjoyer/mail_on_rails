# Recurring wrapper (config/recurring.yml, daily) around SpamhausDrop -
# the import itself, and why it exists, live there.
module MailOnRails
  class SpamhausDropRefreshJob < BaseJob
    queue_as :default
    retry_on StandardError, wait: :polynomially_longer, attempts: 3

    def perform
      SpamhausDrop.refresh!
    end
  end
end
