# Serves a hosted domain's own BIMI logo - the l= target of the
# self-asserted default._bimi TXT DnsPublisher publishes. Anonymous by
# design: receivers' mail systems fetch it (same reasoning as
# MtaStsController). The SVG was sanitized on upload (Domain's
# validation), and the response headers keep even a hypothetical bad one
# inert: no scripts, no external loads, never rendered as a document in
# our origin.
module MailOnRails
  class BimiLogosController < ActionController::Base
    protect_from_forgery with: :exception # GET-only; restore Base's default anyway

    def show
      domain = Domain.find_by(name: params[:domain].to_s.strip.downcase)
      return head :not_found if domain.nil? || domain.bimi_svg.blank?

      response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
      response.headers["X-Content-Type-Options"] = "nosniff"
      response.headers["Cache-Control"] = "public, max-age=86400"
      render plain: domain.bimi_svg, content_type: "image/svg+xml"
    end
  end
end
