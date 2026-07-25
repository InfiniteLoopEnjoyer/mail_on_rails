class DomainsController < ApplicationController
  before_action :set_domain, only: %i[show destroy]

  def index
    @domains = Domain.order(:name)
  end

  def show
  end

  def new
    @domain = Domain.new
  end

  def create
    @domain = Domain.new(domain_params)
    synced = with_sync_alert { @domain.save }
    if @domain.persisted?
      redirect_to @domain, notice: ("Domain #{@domain.name} added. Publish the DNS records below." if synced)
    else
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    synced = with_sync_alert { @domain.destroy! }
    notice = synced ? "Domain #{@domain.name} removed. Exim now refuses mail for it." :
                      "Domain #{@domain.name} removed from the database."
    redirect_to domains_path, notice: notice, status: :see_other
  end

  private

  def set_domain
    @domain = Domain.find(params[:id])
  end

  def domain_params
    params.expect(domain: [ :name ])
  end

  # The DB change commits even when the after-commit exim sync raises
  # (unwritable volume, ...) - surface that instead of pretending the
  # whole action failed, and point at the manual reconcile. Returns false
  # when the sync failed.
  def with_sync_alert
    yield
    true
  rescue EximLocalDomains::Error => e
    flash[:alert] = "Exim sync failed: #{e.message}. " \
                    "Run bin/rails mail_on_rails:domains:sync after fixing it."
    false
  end
end
