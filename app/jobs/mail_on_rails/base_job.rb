# frozen_string_literal: true

module MailOnRails
  # Base class for the gem's jobs. The host app supplies the Active Job
  # queue adapter; retry/discard policy can be added via the load hook.
  class BaseJob < ActiveJob::Base
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_base_job, MailOnRails::BaseJob
