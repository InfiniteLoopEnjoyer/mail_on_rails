# frozen_string_literal: true

# Mounted at "/" by the host app: sending MTAs fetch the MTA-STS policy
# from https://mta-sts.<domain>/.well-known/mta-sts.txt, and mailbox
# providers hit the RFC 8058 one-click unsubscribe endpoint that
# outbound List-Unsubscribe headers point at.
MailOnRails::Engine.routes.draw do
  get ".well-known/mta-sts.txt" => "mta_sts#show"

  # Signed tokens contain non-segment characters (base64 +/=), which
  # arrive percent-encoded; the constraint keeps the format wildcard from
  # eating a trailing ".something" of the token.
  get "unsubscribe/:token" => "unsubscribes#show", constraints: { token: %r{[^/]+} }
  post "unsubscribe/:token" => "unsubscribes#create", constraints: { token: %r{[^/]+} }

  # A hosted domain's own BIMI logo, fetched by receiving mail systems
  # (the l= target of the published default._bimi TXT). The constraint
  # keeps the domain's dots out of the format wildcard.
  get "bimi/:domain/logo.svg" => "bimi_logos#show", constraints: { domain: /[a-z0-9.-]+/ }
end
