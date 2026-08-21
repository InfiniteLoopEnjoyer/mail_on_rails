# The https unsubscribe endpoint the injected List-Unsubscribe headers
# point at (OutboundDeliverer#inject_list_unsubscribe). Anonymous by
# design - the signed UnsubscribeToken is the entire authorization, and
# the POST comes from the recipient's mailbox provider (RFC 8058
# one-click), which has no session or CSRF token.
#
#   GET  /unsubscribe/:token  - human-facing confirmation page with a
#                               button. GET never unsubscribes: link
#                               scanners and prefetchers follow GETs, and
#                               an unsubscribe they trigger is RFC 8058's
#                               whole reason for requiring POST.
#   POST /unsubscribe/:token  - records the sender-scoped suppression.
module MailOnRails
  # Deliberately ActionController::Base, not the host's ApplicationController:
  # recipients and their providers hit this anonymously, so no host auth
  # concern may apply (same reasoning as MtaStsController).
  class UnsubscribesController < ActionController::Base
    # The one-click POST carries no CSRF token; the signed token in the
    # path authorizes the action instead.
    protect_from_forgery with: :null_session

    def show
      return render_invalid unless UnsubscribeToken.verify(params[:token])

      render html: confirmation_page, layout: false
    end

    def create
      data = UnsubscribeToken.verify(params[:token])
      return render_invalid unless data

      record = SuppressedRecipient.record_unsubscribe!(data[:recipient], sender: data[:sender],
                                                       reporter: "one-click")
      Rails.logger.info "[mail_on_rails] one-click unsubscribe recorded: <#{record.email}> from <#{record.sender}>"
      render plain: "You have been unsubscribed and will receive no further mail from this sender.", status: :ok
    end

    private

    # 410 for a dead link: the token names nothing actionable any more,
    # and the status alone tells providers to stop retrying.
    def render_invalid
      render plain: "This unsubscribe link is invalid or has expired.", status: :gone
    end

    # Self-contained page (no host layout/assets): one sentence and a
    # button that POSTs back to this same URL. The token is not echoed
    # into the page body - the form action reuses the request path.
    def confirmation_page
      <<~HTML.html_safe
        <!DOCTYPE html>
        <html><head><title>Unsubscribe</title><meta name="viewport" content="width=device-width, initial-scale=1"></head>
        <body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;">
          <h1 style="font-size: 1.25rem;">Unsubscribe</h1>
          <p>Click the button below to stop receiving this sender's mailing-list messages.</p>
          <form method="post" action="#{ERB::Util.html_escape(request.path)}">
            <button type="submit" style="padding: 0.5rem 1.5rem; font-size: 1rem; cursor: pointer;">Unsubscribe</button>
          </form>
        </body></html>
      HTML
    end
  end
end
