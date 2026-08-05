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

  # The mail servers run inside this process (the :mail_on_rails Puma
  # plugin) and hand inbound mail to Action Mailbox directly
  # (Store::SmtpBackend), so no HTTP ingress exists anymore. Action
  # Mailbox's routes are drawn after this file; pin them closed for
  # everyone with an explicit earlier route answering the same 404 an
  # unknown path would.
  match "rails/action_mailbox/*path", via: :all,
    to: proc { [ 404, { "Content-Type" => "text/plain" }, [ "Not Found\n" ] ] }

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Defines the root path route ("/")
  root "email_accounts#index"

  # Operational internals (the banned_ips file, app-wide knobs) - see
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
  # BannedIp for how they reach the mail listeners and the web login.
  resources :banned_ips, only: %i[create destroy]

  # The signed-in user's appearance/accent preference, saved from the
  # profile's Appearance card - see ThemesController.
  resource :theme, only: :update



  resources :users, except: %i[show] do
    member do
      post :generate_password
    end
  end

  # Domains we host. Create/destroy takes effect at the next RCPT check
  # (Store::SmtpBackend reads the Domain table live). publish_dns creates
  # the domain's missing DNS records in Cloudflare (DnsPublisher).
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
