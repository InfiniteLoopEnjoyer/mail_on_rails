# TODO

Actionable roadmap items live in the README's Roadmap section. What's
left here are the operational notes that aren't code work.

## Operational notes

- **Accessory images aren't Dependabot-watched** (2026-07-29) — the
  `postgres:16` (and registry/kamal-proxy) images live in
  config/deploy.yml, which the docker ecosystem doesn't scan. Low churn;
  bump them manually when advisories land.

- **Deliverability operator checklist** (2026-07-22) — PTR/FCrDNS for the
  sending IP isn't (and can't be) verified by code; also note outbound
  STARTTLS uses `tls_verify: false` (fine for deliverability, worth
  knowing). Via `MAIL_ON_RAILS_SMARTHOST`, SPF is evaluated against the
  smarthost's IP, so its SPF posture is what matters.

