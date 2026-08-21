# frozen_string_literal: true

source "https://rubygems.org"

gemspec

group :development, :test do
  gem "puma"
  # One gem per supported adapter, for the test:db matrix. trilogy rather
  # than mysql2 because it vendors its client - no libmysqlclient needed
  # to run the matrix.
  gem "pg"
  gem "trilogy"
  gem "sqlite3"
  gem "debug", platforms: %i[ mri windows ], require: "debug/prelude"
  gem "rubocop-rails-omakase", require: false
  # Static analysis for security vulnerabilities [https://brakemanscanner.org/]
  gem "brakeman", require: false
end
