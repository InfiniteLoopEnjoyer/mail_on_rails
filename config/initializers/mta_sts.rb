# Validate the published MTA-STS policy configuration at boot: a typo'd
# MAIL_ON_RAILS_MTA_STS_MODE / _MAX_AGE must name itself and fail the
# deploy, not surface as a 500 on the policy endpoint (or worse, publish
# a malformed policy senders then cache). after_initialize because MtaSts
# is an autoloaded model, off-limits during initializer load.
Rails.application.config.after_initialize do
  MtaSts.mode
  MtaSts.max_age
end
