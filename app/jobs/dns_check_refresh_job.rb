# Keeps Domain#dns_checks - the cache behind the domains-index pills -
# fresh: hourly across all domains (config/recurring.yml), and once per
# new domain right after create. Lookup failures land as :unknown checks
# rather than raising, so a flaky resolver never parks the job in retry.
class DnsCheckRefreshJob < ApplicationJob
  queue_as :default
  # The domain was deleted between enqueue and run.
  discard_on ActiveJob::DeserializationError

  def perform(domain = nil)
    return DnsCheck.refresh!(domain) if domain

    Domain.find_each { |d| DnsCheck.refresh!(d) }
  end
end
