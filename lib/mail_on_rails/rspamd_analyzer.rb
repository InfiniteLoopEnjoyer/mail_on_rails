# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module MailOnRails
  # Sends a raw RFC822 message to an rspamd worker's HTTP /checkv2 endpoint
  # to compute the inbound sender-authentication verdicts (SPF/DKIM/DMARC)
  # and a spam action. The exim edge does none of this itself - it only
  # forwards the connection facts (client IP, HELO, envelope sender) as the
  # trusted X-MailOnRails-* / Return-Path headers, which the mailroom passes
  # here so rspamd's SPF/DMARC checks have the data the app never saw on the
  # wire.
  #
  # Twin of MailOnRails::ClamavScanner in shape: enabled by an env address,
  # never raises (any failure is :unavailable, and callers decide policy),
  # read per call so tests can toggle it. Disabled unless SMTP_RSPAMD_ADDR
  # is set (a "host:port" pointing at rspamd's normal worker, default 11333).
  module RspamdAnalyzer
    # `auth_results` is an Authentication-Results-style string built from the
    # mechanism verdicts (e.g. "mail.example.com; spf=pass; dkim=pass;
    # dmarc=pass"), the exact shape EmailMessage#auth_result parses and the
    # mailroom stamps. `action`/`score` carry rspamd's spam verdict for logging.
    Result = Struct.new(:status, :action, :score, :required_score, :spf, :dkim, :dmarc, :auth_results,
                        keyword_init: true) do
      def ok? = status == :ok
      def unavailable? = status == :unavailable
      # Any action past plain acceptance/greylisting is rspamd calling it spam.
      def spam? = ok? && ![ nil, "no action", "greylist" ].include?(action)
    end

    DEFAULT_PORT = 11333
    DEFAULT_TIMEOUT = 10

    # rspamd surfaces each mechanism as a symbol; first match wins (the maps
    # are ordered pass-first). Anything unlisted leaves that mechanism nil,
    # i.e. omitted from the Authentication-Results string.
    SPF_SYMBOLS = {
      "R_SPF_ALLOW" => "pass", "R_SPF_FAIL" => "fail", "R_SPF_SOFTFAIL" => "softfail",
      "R_SPF_NEUTRAL" => "neutral", "R_SPF_DNSFAIL" => "temperror",
      "R_SPF_PERMFAIL" => "permerror", "R_SPF_NA" => "none"
    }.freeze
    DKIM_SYMBOLS = {
      "R_DKIM_ALLOW" => "pass", "R_DKIM_REJECT" => "fail",
      "R_DKIM_TEMPFAIL" => "temperror", "R_DKIM_PERMFAIL" => "permerror", "R_DKIM_NA" => "none"
    }.freeze
    DMARC_SYMBOLS = {
      "DMARC_POLICY_ALLOW" => "pass", "DMARC_POLICY_REJECT" => "fail",
      "DMARC_POLICY_QUARANTINE" => "fail", "DMARC_POLICY_SOFTFAIL" => "fail",
      "DMARC_NA" => "none", "DMARC_BAD_POLICY" => "permerror"
    }.freeze

    module_function

    def enabled?
      !addr.empty?
    end

    def addr
      ENV["SMTP_RSPAMD_ADDR"].to_s.strip
    end

    def timeout
      Integer(ENV.fetch("SMTP_RSPAMD_TIMEOUT", DEFAULT_TIMEOUT))
    end

    # Analyze a message. The keyword facts come from the exim-stamped headers
    # and are passed to rspamd so SPF/DMARC (which need the live connection)
    # can run app-side. Returns a Result; :unavailable on any transport or
    # parse failure - never raises.
    def analyze(raw, ip: nil, helo: nil, mail_from: nil, rcpt: nil, authenticated_as: nil)
      uri = endpoint
      http = Net::HTTP.new(uri.host, uri.port || DEFAULT_PORT)
      http.open_timeout = timeout
      http.read_timeout = timeout
      http.use_ssl = uri.scheme == "https"

      request = Net::HTTP::Post.new("/checkv2")
      request.body = raw
      request["Content-Type"] = "application/octet-stream"
      request["IP"] = clean(ip) if ip
      request["Helo"] = clean(helo) if helo
      request["From"] = clean(mail_from) if mail_from
      request["Rcpt"] = clean(rcpt) if rcpt
      request["User"] = clean(authenticated_as) if authenticated_as
      request["Password"] = clean(password) unless password.empty?

      response = http.request(request)
      return Result.new(status: :unavailable) unless response.is_a?(Net::HTTPSuccess)

      parse(JSON.parse(response.body))
    rescue Timeout::Error, SystemCallError, IOError, SocketError, Net::ProtocolError, JSON::ParserError
      Result.new(status: :unavailable)
    end

    def parse(json)
      symbols = json["symbols"] || {}
      spf = mechanism(symbols, SPF_SYMBOLS)
      dkim = mechanism(symbols, DKIM_SYMBOLS)
      dmarc = mechanism(symbols, DMARC_SYMBOLS)

      Result.new(
        status: :ok, action: json["action"], score: json["score"], required_score: json["required_score"],
        spf: spf, dkim: dkim, dmarc: dmarc, auth_results: auth_results_string(spf, dkim, dmarc)
      )
    end

    def mechanism(symbols, map)
      map.each { |symbol, verdict| return verdict if symbols.key?(symbol) }
      nil
    end

    def auth_results_string(spf, dkim, dmarc)
      parts = []
      parts << "spf=#{spf}" if spf
      parts << "dkim=#{dkim}" if dkim
      parts << "dmarc=#{dmarc}" if dmarc
      return if parts.empty?

      "#{authserv_id}; #{parts.join('; ')}"
    end

    def authserv_id
      host = ENV["SMTP_HELO_HOST"].to_s.strip
      host.empty? ? "mail-on-rails" : host
    end

    def password
      ENV["SMTP_RSPAMD_PASSWORD"].to_s.strip
    end

    def endpoint
      base = addr.include?("://") ? addr : "http://#{addr}"
      URI.parse(base)
    end

    # Header values cross a trust boundary into rspamd's request line; strip
    # CR/LF so a hostile envelope value can't inject extra headers.
    def clean(value)
      value.to_s.gsub(/[\r\n]/, "").strip
    end
  end
end
