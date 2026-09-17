# frozen_string_literal: true

module MailOnRails
  # Decides an idle_auto_ban once BannedIp::IDLE_BAN_GRACE has passed since
  # the address reached the threshold (enqueued by BannedIp.idle_strike). Off
  # the connection thread because the decision does a blocking reverse-DNS
  # lookup, and late because the address may yet log in. No retries: a ban
  # that could not be decided this time is asked for again by the address's
  # next idle connection.
  class IdleBanJob < BaseJob
    queue_as :default

    def perform(ip, protocol, reason)
      BannedIp.auto_ban_for_idle(ip: ip, protocol: protocol, reason: reason)
    end
  end
end
