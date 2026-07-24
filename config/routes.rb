Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Private API for the mail edges - the exim service (authenticate +
  # outbound_messages) and the IMAP daemon (imap/:op) - basic-auth'd with
  # credentials mail_on_rails.internal_api_password, so those services hold
  # no database connection at all. See MailOnRails::InternalController.
  scope "mail_on_rails/internal", controller: "mail_on_rails/internal" do
    post :authenticate, action: :authenticate, as: :mail_on_rails_internal_authenticate
    post :rcpt_check, action: :rcpt_check, as: :mail_on_rails_internal_rcpt_check
    post :outbound_messages, action: :create_outbound, as: :mail_on_rails_internal_outbound_messages
    post "imap/:op", action: :imap, as: :mail_on_rails_internal_imap, constraints: { op: /[a-z_]+/ }
  end

  # Defines the root path route ("/")
  root "email_accounts#index"

  resources :users, except: %i[show]

  resources :email_accounts, path: "accounts" do
    resources :mailboxes, except: %i[index] do
      resources :email_messages, only: %i[show], path: "messages"
    end
  end
end
