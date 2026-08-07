# The composer uses the <lexxy-editor> element directly (see
# drafts/_composer); this app has no Action Text models, so Lexxy's
# takeover of form.rich_text_area is surface area nobody exercises.
# Keeping it off means Action Text behaves stock if it is ever adopted.
Rails.application.config.lexxy.override_action_text_defaults = false
