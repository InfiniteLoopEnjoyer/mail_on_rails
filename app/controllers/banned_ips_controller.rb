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
      kicked = kick_live_connections(banned_ip)
      notice = [ ("Banned #{banned_ip.cidr}." if synced),
                 ("Dropped #{kicked} live #{"connection".pluralize(kicked)}." if kicked.positive?) ].compact.join(" ")
      redirect_back_to_attempts notice: notice.presence
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

  # The mail servers run inside this very process (the :mail_on_rails
  # Puma plugin), so a new ban can also drop the address's live
  # connections - the denylist files only silence future ones, and an
  # established IMAP IDLE would otherwise outlive the ban by up to its
  # 1800s idle timeout. A no-server boot (tests, plain `rails server`)
  # just kicks nothing.
  def kick_live_connections(banned_ip)
    require "mail_on_rails/boot"
    MailOnRails::Boot.kick_connections do |ip|
      banned_ip.covers_addr?(IPAddr.new(ip))
    rescue IPAddr::Error
      false
    end
  end

  # The actions live as buttons on the auth attempts index, its range
  # drill-down, and the SMTP/IMAP live connection pages; origin/cidr/
  # window params say which one to return to.
  def redirect_back_to_attempts(**options)
    target = case params[:origin]
    when "smtp" then smtp_path
    when "imap" then imap_path
    else
      if params[:range].present?
        range_auth_attempts_path(cidr: params[:range], window: params[:window])
      else
        auth_attempts_path(window: params[:window])
      end
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
