# Create/remove permanent IP bans from the auth attempts pages (inline
# ban buttons and the manual form - no pages of its own, both actions land
# back where they were clicked, on the index or a range drill-down).
class BannedIpsController < ApplicationController
  def create
    banned_ip = BannedIp.new(banned_ip_params)

    # A ban that covers the address you're browsing from is almost
    # certainly a mistake, and with the web login also enforcing bans it
    # would lock this very account out. Refuse outright; nothing stops a
    # deliberate ban of the range from another network.
    if covers_own_ip?(banned_ip)
      return redirect_back_to_attempts alert:
        "Refusing to ban #{banned_ip.cidr}: it covers your own address (#{request.remote_ip})."
    end

    synced = with_sync_alert { banned_ip.save }
    if banned_ip.persisted?
      redirect_back_to_attempts notice: ("Banned #{banned_ip.cidr}." if synced)
    else
      redirect_back_to_attempts alert:
        "Ban not added: #{banned_ip.errors.full_messages.to_sentence}."
    end
  end

  def destroy
    banned_ip = BannedIp.find(params[:id])
    synced = with_sync_alert { banned_ip.destroy! }
    redirect_back_to_attempts status: :see_other,
      notice: ("Unbanned #{banned_ip.cidr}." if synced)
  end

  private

  def banned_ip_params
    params.expect(banned_ip: [ :cidr, :note ])
  end

  def covers_own_ip?(banned_ip)
    banned_ip.valid? # runs normalization so we test the CIDR that would be saved
    addr = IPAddr.new(request.remote_ip)
    banned_ip.covers_addr?(addr)
  rescue IPAddr::Error
    false
  end

  # Both actions live as buttons on the auth attempts index and its range
  # drill-down; cidr/window params say which one to return to.
  def redirect_back_to_attempts(**options)
    target = if params[:range].present?
      range_auth_attempts_path(cidr: params[:range], window: params[:window])
    else
      auth_attempts_path(window: params[:window])
    end
    redirect_to target, **options
  end

  # The DB change commits even when the after-commit file sync raises
  # (unwritable volume, ...) - surface that instead of pretending the
  # whole action failed, and point at the manual reconcile. Returns false
  # when the sync failed.
  def with_sync_alert
    yield
    true
  rescue BannedIpsFile::Error => e
    flash[:alert] = "Banned IPs sync failed: #{e.message}. " \
                    "Run bin/rails mail_on_rails:banned_ips:sync after fixing it."
    false
  end
end
