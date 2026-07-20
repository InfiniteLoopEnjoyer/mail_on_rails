if Rails.env.development?

  # App login (Rails 8 authentication). This is the web UI login, separate
  # from the mail identities below - one signed-in user can browse every
  # mail account.
  User.find_or_create_by!(email_address: "admin@mailonrails.test") do |user|
    user.password = "password123"
  end
  puts "App login: admin@mailonrails.test / password123"

  # Development accounts for the mail_on_rails SMTP/IMAP servers.
  # IMAP/SMTP login: full email address + the password below.

  accounts = [
    { email: "alice@mailonrails.test", name: "Alice" },
    { email: "bob@mailonrails.test", name: "Bob" }
  ]

  accounts.each do |attrs|
    EmailAccount.find_or_create_by!(email: attrs[:email]) do |account|
      account.name = attrs[:name]
      account.password = "password123"
    end
  end

  alice = EmailAccount.find_by!(email: "alice@mailonrails.test")

  if alice.inbox.email_messages.none?
    welcome = Mail.new do
      from "bob@mailonrails.test"
      to "alice@mailonrails.test"
      subject "Welcome to mail_on_rails"
      date Time.current
      body <<~BODY
        Hi Alice,

        This message was seeded into your INBOX. Try reading it over IMAP
        (localhost:1143) or sending a new one over SMTP (localhost:1025).

        - Bob
      BODY
    end
    EmailMessage.deliver_raw(alice.inbox, welcome.to_s)

    puts "Seeded welcome message into #{alice.email}'s INBOX"
  end

  puts "Accounts: #{EmailAccount.pluck(:email).join(", ")} (password: password123)"

end
