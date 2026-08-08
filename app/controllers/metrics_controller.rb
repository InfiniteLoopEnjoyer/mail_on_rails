require "mail_on_rails/rspamd_analyzer"

# Prometheus exposition endpoint (/metrics), following kamal-proxy's
# promhttp precedent. Everything is computed on scrape from what the app
# already records - no in-process counters to lose on restart:
#
#   - outbound queue depth by status and the due backlog
#     (SmtpOutboundMessage - the number to alert on);
#   - delivery latency (queued -> sent) over the last hour, as a
#     summary's sum/count so rate() gives the average;
#   - rejection tallies: auth failures by protocol (AuthAttempt) and
#     quarantined/junked message counts;
#   - storage: accounts, messages, used bytes;
#   - live SMTP/IMAP connection counts from the in-process servers.
#
# Auth: Prometheus can't do cookies, so the endpoint is enabled by
# setting METRICS_TOKEN and scraping with that bearer token. Unset =
# 404, indistinguishable from the route not existing. METRICS_ALLOW_IPS
# (comma-separated IPs/CIDRs) additionally pins the endpoint to the
# scraper's addresses, so a leaked token alone stops being enough - the
# metrics are operational intelligence (queue depths, auth-failure
# rates, live connections) worth keeping from an attacker casing the
# server. Off-network callers get the same 404 as an unset token.
class MetricsController < ApplicationController
  allow_unauthenticated_access
  # No session, no CSRF surface; the bearer token is the whole gate.
  skip_forgery_protection

  def show
    token = ENV["METRICS_TOKEN"].to_s
    head :not_found and return if token.empty? || !allowed_ip?
    head :unauthorized and return unless authorized?(token)

    render plain: render_metrics, content_type: "text/plain; version=0.0.4; charset=utf-8"
  end

  private

  def authorized?(token)
    presented = request.authorization.to_s.delete_prefix("Bearer ").strip
    ActiveSupport::SecurityUtils.secure_compare(presented, token)
  end

  # remote_ip is trustworthy here: kamal-proxy overwrites X-Forwarded-For
  # with the socket peer, so a client can't spoof its way in. An entry
  # that fails to parse is treated as matching nothing (fail closed) -
  # a typo must not silently open the endpoint to everyone.
  def allowed_ip?
    entries = ENV["METRICS_ALLOW_IPS"].to_s.split(",").map(&:strip).reject(&:empty?)
    return true if entries.empty?

    ip = IPAddr.new(request.remote_ip)
    entries.any? do |entry|
      IPAddr.new(entry).include?(ip)
    rescue IPAddr::Error
      false
    end
  rescue IPAddr::Error
    false
  end

  def render_metrics
    out = +""

    emit out, "mail_on_rails_outbound_queue", :gauge,
         "Outbound deliveries by status.",
         SmtpOutboundMessage.group(:status).count.map { |status, n| [ { status: status }, n ] }
    emit out, "mail_on_rails_outbound_due", :gauge,
         "Outbound deliveries due for an attempt now.",
         [ [ {}, SmtpOutboundMessage.due.count ] ]

    sent = SmtpOutboundMessage.sent.where(sent_at: 1.hour.ago..)
    latency = sent.pick(Arel.sql("COALESCE(SUM(EXTRACT(EPOCH FROM sent_at - created_at)), 0), COUNT(*)"))
    out << "# HELP mail_on_rails_outbound_delivery_seconds Queued-to-sent latency, last hour.\n"
    out << "# TYPE mail_on_rails_outbound_delivery_seconds summary\n"
    out << "mail_on_rails_outbound_delivery_seconds_sum #{latency[0].to_f}\n"
    out << "mail_on_rails_outbound_delivery_seconds_count #{latency[1]}\n"

    emit out, "mail_on_rails_auth_failures", :gauge,
         "Failed credential checks currently retained, by protocol.",
         AuthAttempt.group(:source).sum(:attempt_count).map { |source, n| [ { protocol: source }, n ] }
    emit out, "mail_on_rails_messages_flagged", :gauge,
         "Messages sitting in review mailboxes.",
         [ [ { mailbox: "quarantine" }, Mailbox.where(name: Mailbox::QUARANTINE).joins(:email_messages).count ],
           [ { mailbox: "junk" }, Mailbox.where(name: Mailbox::JUNK).joins(:email_messages).count ] ]

    emit out, "mail_on_rails_accounts", :gauge, "Hosted email accounts.",
         [ [ {}, EmailAccount.count ] ]
    emit out, "mail_on_rails_messages", :gauge, "Stored messages.",
         [ [ {}, EmailMessage.count ] ]
    emit out, "mail_on_rails_storage_used_bytes", :gauge,
         "Sum of stored message bytes across accounts.",
         [ [ {}, EmailAccount.sum(:used_bytes) ] ]

    emit out, "mail_on_rails_live_connections", :gauge,
         "Open connections on the in-process mail listeners.",
         %i[smtp imap].map { |proto| [ { protocol: proto }, live_connections(proto) ] }

    # Only when rspamd is configured - a hardwired 0 on setups that never
    # enabled it would page about a service that isn't supposed to exist.
    # Worth alerting on: authenticated submission fails OPEN when rspamd
    # is down, so "rspamd_up == 0 and outbound volume climbing" is the
    # signature of a compromised account spamming unchecked.
    if MailOnRails::RspamdAnalyzer.enabled?
      emit out, "mail_on_rails_rspamd_up", :gauge,
           "1 when the configured rspamd worker answers /ping.",
           [ [ {}, MailOnRails::RspamdAnalyzer.up? ? 1 : 0 ] ]
    end

    out
  end

  def emit(out, name, type, help, series)
    out << "# HELP #{name} #{help}\n# TYPE #{name} #{type}\n"
    series.each do |labels, value|
      rendered = labels.map { |k, v| "#{k}=\"#{v}\"" }.join(",")
      out << "#{name}#{rendered.empty? ? "" : "{#{rendered}}"} #{value}\n"
    end
  end

  def live_connections(protocol)
    require "mail_on_rails/boot"
    MailOnRails::Boot.server(protocol)&.connections&.size || 0
  end
end
