Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # The Action Mailbox relay ingress is only ever posted to by the exim edge,
  # which reaches the app over the docker network (its INGRESS_URL resolves to
  # kamal-proxy's network alias), so every legitimate client IP is private.
  # On top of the ingress password, refuse the endpoint to public clients
  # entirely: this route is drawn before Action Mailbox's engine routes, so a
  # non-local request matches it and gets the same 404 an unknown path would,
  # while local requests fail the constraint and fall through to the real
  # ingress. kamal-proxy appends the true client IP to X-Forwarded-For, so a
  # spoofed private address in that header still resolves to the public IP.
  non_local = lambda do |request|
    ip = begin
      IPAddr.new(request.remote_ip)
    rescue IPAddr::Error
      nil
    end
    ip.nil? || !(ip.loopback? || ip.private?)
  end
  match "rails/action_mailbox/*path", via: :all, constraints: non_local,
    to: proc { [ 404, { "Content-Type" => "text/plain" }, [ "Not Found\n" ] ] }

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Private API for the mail edges - the exim service (authenticate +
  # outbound_messages) and the IMAP daemon (imap/:op) - basic-auth'd with
  # credentials mail_on_rails.internal_api_password, so those services hold
  # no database connection at all. See MailOnRails::InternalController.
  scope "mail_on_rails/internal", controller: "mail_on_rails/internal" do
    post :authenticate, action: :authenticate, as: :mail_on_rails_internal_authenticate
    post :outbound_messages, action: :create_outbound, as: :mail_on_rails_internal_outbound_messages
    post "imap/:op", action: :imap, as: :mail_on_rails_internal_imap, constraints: { op: /[a-z_]+/ }
  end

  # Defines the root path route ("/")
  root "email_accounts#index"

  # Operational internals (exim's shared-volume files, ...) - see
  # SettingsController.
  resource :settings, only: :show



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

  resources :email_accounts, path: "accounts" do
    member do
      post :generate_password
    end
    resources :mailboxes, except: %i[index] do
      resources :email_messages, only: %i[show], path: "messages" do
        member do
          post :mark_read
        end
      end
    end
  end
end
