# TODO
## Supply-chain hardening follow-ups (2026-07-29)

Deferred items from the Docker/Omdia supply-chain report review (CI for the
daemon repos, scheduled scans, Trivy image scanning, digest-pinned base
images, and Dependabot docker ecosystems in all three repos are done):

- **Accessory images aren't Dependabot-watched** — the `postgres:16` (and
  registry/kamal-proxy) images live in config/deploy.yml, which the docker
  ecosystem doesn't scan. Low churn; bump them manually when advisories
  land.

- **Pin GitHub Actions to commit SHAs** — `actions/checkout@v7` etc. are
  mutable tags (the tj-actions/changed-files compromise worked by
  retargeting tags). Pin to full SHAs with the version in a trailing
  comment in all three repos' workflows; Dependabot understands and
  updates SHA pins.

## Outbound deliverability (DKIM/SPF/DMARC audit, 2026-07-22)

Audit of `DeliverSmtpOutboundJob` → `OutboundDeliverer`:

- **SPF: DNS-only, nothing enforces it** — code only exposes
  `SMTP_HELO_HOST`; nothing verifies the published SPF record
  includes the sending IP. Covered by the "Domain-setup DNS checker"
  item below. Note: via `MAIL_ON_RAILS_SMARTHOST`, SPF is evaluated
  against the smarthost's IP, so its SPF posture is what matters.
- **DMARC: passes when the above hold** — needs aligned DKIM *or*
  aligned SPF; with a key present and envelope-from == header-from,
  outbound passes. No code needed beyond the alignment fix above.
- **Not covered by code (operator checklist)** — PTR/FCrDNS for the
  sending IP; also note outbound STARTTLS uses `tls_verify: false`
  (fine for deliverability, worth knowing).
