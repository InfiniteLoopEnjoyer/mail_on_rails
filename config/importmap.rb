# Pin npm packages by running ./bin/importmap

pin "application"
pin "@hotwired/turbo-rails", to: "turbo.min.js"
pin "@hotwired/stimulus", to: "stimulus.min.js"
pin "@hotwired/stimulus-loading", to: "stimulus-loading.js"
# The composer's rich-text editor (Lexical bundled inside; no Node build).
# lexxy.js lazily imports @rails/activestorage for attachment uploads; the
# composer disables attachments, but the pin keeps the import resolvable.
pin "lexxy", to: "lexxy.js"
pin "@rails/activestorage", to: "activestorage.esm.js"
pin_all_from "app/javascript/controllers", under: "controllers"
