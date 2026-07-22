# CI review: internal API auth failures in test environment

## Root cause

`MailOnRails::InternalController` currently authenticates internal API requests using only Rails encrypted credentials:

- `Rails.application.credentials.dig(:mail_on_rails, :internal_api_password)`

In CI, this value is missing or not decryptable, so it resolves blank and all internal API requests fail with `401 Unauthorized`, causing the controller tests to fail.

## Proposed code change

Add an environment-variable fallback so CI and daemon-style deploys can provide the password without requiring credentials decryption.

### File: `app/controllers/mail_on_rails/internal_controller.rb`

```diff
@@
   def require_internal_api_password
     authenticate_or_request_with_http_basic do |_user, password|
-      expected = Rails.application.credentials.dig(:mail_on_rails, :internal_api_password).to_s
+      expected = ENV["SMTP_INTERNAL_API_PASSWORD"].presence ||
+                 Rails.application.credentials.dig(:mail_on_rails, :internal_api_password).to_s
       expected.present? && ActiveSupport::SecurityUtils.secure_compare(password, expected)
     end
   end
 end
```

## CI workflow follow-up

After the code change above, define `SMTP_INTERNAL_API_PASSWORD` in test jobs for GitHub Actions so tests are deterministic.

Example snippet for `.github/workflows/ci.yml` test jobs:

```yaml
env:
  RAILS_ENV: test
  DATABASE_HOST: 127.0.0.1
  DATABASE_PORT: 5432
  DATABASE_USERNAME: postgres
  DATABASE_PASSWORD: postgres
  SMTP_INTERNAL_API_PASSWORD: test-internal-api-password
```

## Optional test hardening

To avoid dependence on machine credentials, tests can temporarily set the env var in setup/teardown around internal API tests.
