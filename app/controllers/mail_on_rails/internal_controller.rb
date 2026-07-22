# The private HTTP API the SMTP daemon uses instead of a database
# connection (its inbound handoff uses Action Mailbox's relay ingress; the
# three operations here cover everything else the SMTP store contract
# needs). Endpoints are POST-only JSON, authenticated with HTTP basic auth
# against MAIL_ON_RAILS_INTERNAL_API_PASSWORD (env, used by CI where no
# RAILS_MASTER_KEY exists) falling back to credentials
# mail_on_rails.internal_api_password - the daemons hold a copy as an env
# secret (MAIL_ON_RAILS_INTERNAL_API_PASSWORD in their deploy configs), so
# no RAILS_MASTER_KEY leaves this app.
# lib/mail_on_rails is on the autoload ignore list (see config/application.rb),
# so the store must be required explicitly. Previously the in-process
# daemon boot happened to load it before the first request; now that the
# daemons live out of process, this controller is the only consumer.
require "mail_on_rails/store"

class MailOnRails::InternalController < ActionController::API
  include ActionController::HttpAuthentication::Basic::ControllerMethods

  before_action :require_internal_api_password

  # Credential check for SMTP AUTH. Mirrors the store contract's
  # authenticate: both fields null on failure (a 200, not a 401 - the 401
  # space belongs to the API password above).
  def authenticate
    account = EmailAccount.authenticate_by(
      email: params.require(:email), password: params.require(:password)
    )
    render json: { account_id: account&.id, email: account&.email }
  end

  # RCPT TO validation: which of these addresses are local accounts?
  def rcpt_check
    normalized = Array(params[:addresses]).map { |a| a.to_s.strip.downcase }.uniq
    render json: { local: EmailAccount.where(email: normalized).pluck(:email) }
  end

  # Queue outbound mail (authenticated submission to remote recipients),
  # one row per recipient, all-or-nothing. The raw message is the request
  # body; recipients/sender ride the query string. 507 when the queue cap
  # is hit - the daemon maps it to "452 try later".
  def create_outbound
    recipients = Array(params[:rcpt]).map { |r| r.to_s.strip }.reject(&:empty?)
    return head :unprocessable_entity if recipients.empty?

    if SmtpOutboundMessage.pending.count + recipients.size > outbound_limit
      return head :insufficient_storage
    end

    data = request.body.read
    return head :unprocessable_entity if data.empty?

    SmtpOutboundMessage.transaction do
      recipients.each do |recipient|
        SmtpOutboundMessage.create!(
          mail_from: params[:mail_from], recipient: recipient,
          data: data, next_attempt_at: Time.current
        )
      end
    end
    head :created
  end

  # The IMAP store contract over HTTP: one endpoint per operation
  # (POST imap/:op), delegating to the Active Record implementation.
  # Results are plain values (docs/store_contract.md), so they render as
  # JSON directly - except raw message bytes, which are base64-framed
  # (raw_base64) both directions because raw mail is arbitrary binary.
  def imap
    backend = MailOnRails::Store::ImapBackend.new
    result =
      case params[:op]
      when "list_mailboxes" then backend.list_mailboxes(params[:account_id].to_i)
      when "create_mailbox" then backend.create_mailbox(params[:account_id].to_i, params[:name].to_s)
      when "select_mailbox" then backend.select_mailbox(params[:account_id].to_i, params[:name].to_s)
      when "status" then backend.status(params[:account_id].to_i, params[:name].to_s)
      when "fetch" then encode_raws(backend.fetch(params[:mailbox_id].to_i, int_list(:uids), params[:with_raw] == true))
      when "store_flags" then backend.store_flags(params[:mailbox_id].to_i, int_list(:uids), params[:mode].to_s, string_list(:flags))
      when "expunge" then backend.expunge(params[:mailbox_id].to_i)
      when "append" then backend.append(params[:account_id].to_i, params[:mailbox_name].to_s,
                                        params[:raw_base64].to_s.unpack1("m0"), string_list(:flags),
                                        params[:internal_date_epoch]&.to_i)
      when "copy" then backend.copy(params[:mailbox_id].to_i, int_list(:uids), params[:dest_name].to_s)
      else return head :not_found
      end
    render json: result
  end

  private

  # Bounds the outbound queue (authenticated senders only, but still).
  def outbound_limit
    Integer(ENV.fetch("MAIL_ON_RAILS_OUTBOUND_LIMIT", 1_000))
  end

  def int_list(key)
    Array(params[key]).map(&:to_i)
  end

  def string_list(key)
    Array(params[key]).map(&:to_s)
  end

  def encode_raws(result)
    Array(result[:messages]).each do |message|
      message[:raw_base64] = [ message.delete(:raw) ].pack("m0") if message.is_a?(Hash) && message.key?(:raw)
    end
    result
  end

  def require_internal_api_password
    authenticate_or_request_with_http_basic do |_user, password|
      expected = ENV["MAIL_ON_RAILS_INTERNAL_API_PASSWORD"].presence ||
                 Rails.application.credentials.dig(:mail_on_rails, :internal_api_password).to_s
      expected.present? && ActiveSupport::SecurityUtils.secure_compare(password, expected)
    end
  end
end
