Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token

  # Two-factor auth. The challenge is the login-time second step (password
  # accepted, session not yet started - see SessionsController#create);
  # passkeys/totp manage enrollment from the user's own edit page.
  namespace :two_factor do
    resource :challenge, only: :new do
      post :webauthn_options
      post :webauthn
      post :totp
    end
    resources :passkeys, only: %i[create destroy] do
      collection { post :options }
    end
    resource :totp, only: %i[new create destroy], controller: "totp"
  end
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Health status on /up: 200 once the app booted with no exceptions AND
  # (in deploys running the in-process mail servers) the SMTP/IMAP
  # listeners are bound - kamal must not consider a container healthy
  # while its mail ports are down. See HealthController.
  get "up" => "health#show", as: :rails_health_check

  # The mail edges (exim, the IMAP daemon) reach the app over the docker
  # network - their INGRESS_URL / INTERNAL_API_URL resolve to kamal-proxy's
  # network alias - so every legitimate client IP on those endpoints is
  # private. On top of their password auth, refuse them to public clients
  # entirely. kamal-proxy appends the true client IP to X-Forwarded-For, so a
  # spoofed private address in that header still resolves to the public IP.
  local_client = lambda do |request|
    ip = begin
      IPAddr.new(request.remote_ip)
    rescue IPAddr::Error
      nil
    end
    !ip.nil? && (ip.loopback? || ip.private?)
  end
  non_local = ->(request) { !local_client.call(request) }

  # Action Mailbox's routes are drawn after this file, so blocking public
  # clients takes an explicit earlier route: a non-local request matches it
  # and gets the same 404 an unknown path would, while local requests fail
  # the constraint and fall through to the real relay ingress.
  match "rails/action_mailbox/*path", via: :all, constraints: non_local,
    to: proc { [ 404, { "Content-Type" => "text/plain" }, [ "Not Found\n" ] ] }

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Private API for the mail edges - the exim service (authenticate +
  # outbound_messages) and the IMAP daemon (imap/:op) - basic-auth'd with
  # credentials mail_on_rails.internal_api_password, so those services hold
  # no database connection at all. See MailOnRails::InternalController.
  # Local clients only: public requests fail the constraint, match nothing,
  # and 404.
  scope "mail_on_rails/internal", controller: "mail_on_rails/internal",
        constraints: local_client do
    post :authenticate, action: :authenticate, as: :mail_on_rails_internal_authenticate
    post :outbound_messages, action: :create_outbound, as: :mail_on_rails_internal_outbound_messages
    post "imap/:op", action: :imap, as: :mail_on_rails_internal_imap, constraints: { op: /[a-z_]+/ }
  end

  # Defines the root path route ("/")
  root "email_accounts#index"

  # Operational internals (exim's shared-volume files, ...) - see
  # SettingsController.
  resource :settings, only: %i[show update] do
    post :sync
  end

  # Failed credential checks across all three auth surfaces - see
  # AuthAttempt / AuthAttemptsController. range drills into one /24's
  # individual addresses; its CIDR travels as a query param because of
  # the slash.
  resources :auth_attempts, only: :index do
    collection { get :range }
  end

  # Permanent IP/CIDR bans, managed from the auth attempts page - see
  # BannedIp for how they reach exim, the IMAP daemon and the web login.
  resources :banned_ips, only: %i[create destroy]

  # The signed-in user's appearance/accent preference, saved from the
  # profile's Appearance card - see ThemesController.
  resource :theme, only: :update



  resources :users, except: %i[show] do
    member do
      post :generate_password
    end
  end

  # Domains we host. Create/destroy rewrites the exim edge's local_domains
  # file live (shared volume) - see Domain / EximLocalDomains. publish_dns
  # creates the domain's missing DNS records in Cloudflare (DnsPublisher).
  resources :domains, only: %i[index new create show destroy] do
    member do
      post :publish_dns
    end
  end

  # Web-UI compose (ComposedEmail); ?from= preselects the sending account.
  resources :emails, only: %i[new create]

  # Composer autosave. A draft is a message in the Drafts mailbox, so each
  # save replaces the previous revision - see EmailDraft.
  resources :drafts, only: %i[edit create destroy]

  resources :email_accounts, path: "accounts" do
    member do
      post :generate_password
    end
    resources :email_aliases, only: %i[create destroy], path: "aliases"
    resources :mailboxes, except: %i[index] do
      resources :email_messages, only: %i[show destroy], path: "messages" do
        member do
          post :mark_read
          post :rescan
          post :mark_spam
          post :unmark_spam
          get "attachments/:index", action: :attachment, as: :attachment, constraints: { index: /\d+/ }
        end
      end
    end
  end
end
