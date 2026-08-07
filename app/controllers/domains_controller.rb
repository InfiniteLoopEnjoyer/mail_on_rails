class DomainsController < ApplicationController
  before_action :set_domain, only: %i[show destroy publish_dns recheck_dns]
  # Tighter than the other admin surfaces: publish_dns calls the
  # Cloudflare API and destroy cuts off a domain's inbound mail.
  rate_limit to: 10, within: 3.minutes, only: %i[create destroy publish_dns recheck_dns],
             with: -> { redirect_to domains_path, alert: "Try again later." }

  def index
    @domains = Domain.order(:name)
  end

  def show
    # refresh! rather than for: the live check doubles as a write-through
    # refresh of the index-pill cache.
    @dns = DnsCheck.refresh!(@domain)
    @dmarc_stats = DmarcReport.stats(@domain)
    @dmarc_advice = @domain.dmarc_advice(@dmarc_stats, @dns.dmarc_record)
  end

  def new
    @domain = Domain.new
  end

  def create
    @domain = Domain.new(domain_params)
    if @domain.save
      audit "domain.create", @domain
      redirect_to @domain, notice: "Domain #{@domain.name} added. Publish the DNS records below."
    else
      render :new, status: :unprocessable_entity
    end
  end

  # Explicit admin action: create this domain's missing DNS records in
  # Cloudflare (see DnsPublisher for what is and isn't touched).
  def publish_dns
    unless CloudflareDns.enabled?
      return redirect_to @domain, alert: "CLOUDFLARE_API_TOKEN is not configured."
    end

    result = DnsPublisher.publish!(@domain)
    audit "domain.publish_dns", @domain, actions: result.actions, skipped: result.skipped
    notice = result.actions.any? ? "Cloudflare: #{result.actions.join("; ")}." : "Cloudflare: nothing to publish."
    notice += " Skipped: #{result.skipped.join("; ")}." if result.skipped.any?
    redirect_to @domain, notice: notice
  rescue CloudflareDns::Error => e
    redirect_to @domain, alert: "Cloudflare publish failed: #{e.message}"
  end

  # Explicit recheck button; show itself re-runs the live check on render.
  def recheck_dns
    redirect_to @domain, notice: "DNS rechecked against public DNS."
  end

  def destroy
    @domain.destroy!
    audit "domain.destroy", @domain
    redirect_to domains_path, notice: "Domain #{@domain.name} removed. Inbound mail for it is now refused.",
                              status: :see_other
  end

  private

  def set_domain
    @domain = Domain.find(params[:id])
  end

  def domain_params
    params.expect(domain: [ :name ])
  end
end
