# TODO
## If the composer ever grows rich-text/HTML sending (noted 2026-08-06)

The web composer is immune to the email-HTML-injection class today only
because it sends text/plain exclusively (`ComposedEmail#build_raw` sets a
bare `mail.body`, no HTML part is ever assembled from user input). Adding
rich-text sending makes that class live:

- Build the HTML part with a templating layer or an editor that emits
  constrained markup - never by concatenating user strings.
- Run the outbound HTML through `EmailHtmlSanitizer` as well,
  belt-and-suspenders on our own output.
- Keep relying on the Mail gem for header encoding (verified 2026-08-06:
  CRLF in subject/display name serializes as =0D=0A, no header injection),
  and keep the whitespace-rejecting recipient validation.

## HTML mail rendering follow-up (2026-08-06)

- **Sanitize `<style>` blocks instead of dropping them** —
  `EmailHtmlSanitizer` currently prunes `<style>` elements entirely, so
  newsletters that rely on stylesheet rules (rather than inline styles)
  render degraded. Follow-up: parse the stylesheet with Crass (already a
  transitive dependency via Loofah), keep qualified rules whose
  declarations pass `Loofah::HTML5::Scrub.scrub_css`, recurse into
  `@media`, drop everything else (`@import`, `url()`, unknown at-rules),
  and re-serialize from the Crass AST — never from the raw text. The
  sandboxed iframe stays the second layer regardless.

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
