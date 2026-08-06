module ApplicationHelper
  # The signed-in user's theme, defaults for the login/reset pages. Painted
  # onto <html> so dark pages render dark from the first byte; "system" is
  # resolved client-side by the inline script in the layout head.
  def current_appearance = (authenticated? ? Current.user.appearance : "system")
  def current_accent     = (authenticated? ? Current.user.accent : "crimson")

  # Sets the <title> as "Mail on Rails - <subtitle>".
  def page_title(subtitle)
    content_for :title, "Mail on Rails - #{subtitle}"
  end

  # Section predicates for the sidebar nav. Mailboxes is the child of Domains
  # and owns the whole account/mailbox/message drill-down.
  def domains_section?   = controller_name == "domains"
  def users_section?     = controller_name == "users" || controller_path.start_with?("two_factor/")
  def settings_section?  = controller_name == "settings"
  def mailboxes_section? = %w[email_accounts mailboxes email_messages].include?(controller_name)
  def smtp_section?      = controller_name == "smtp"
  def imap_section?      = controller_name == "imap"
  def security_section?  = controller_name == "auth_attempts"

  # Window selector on the auth attempts page. Class literals again, so
  # Tailwind's scanner sees them.
  def window_tab_classes(active)
    base = "rounded-md px-2.5 py-1 text-sm"
    active ? "#{base} bg-accent/10 font-medium text-accent"
           : "#{base} text-slate-500 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-800 dark:hover:text-slate-100"
  end

  # Sidebar link classes; child items are indented + a shade lighter to read
  # as nested. Keep every class literal so Tailwind's scanner sees them.
  def nav_link_classes(active, child: false)
    base  = child ? "block rounded-md py-1.5 pr-3 pl-9 text-sm" \
                  : "block rounded-md px-3 py-2 text-sm font-medium"
    state =
      if active
        "bg-accent/10 font-medium text-accent"
      elsif child
        "text-slate-400 dark:text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-600 dark:hover:text-slate-300"
      else
        "text-slate-500 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-800 dark:hover:text-slate-100"
      end
    "#{base} #{state}"
  end

  # Tailwind bg/text classes for a sender-auth verdict badge (spf/dkim/dmarc),
  # bucketed by how the mechanism landed. Used by the received-message
  # analysis footer.
  def auth_badge_classes(verdict)
    case verdict
    when "pass"                             then "bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-400"
    when "fail", "permerror", "temperror"   then "bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-400"
    when "softfail", "neutral"              then "bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-400"
    else                                         "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
    end
  end

  # Badge text for a sender-auth verdict, e.g. "✓ SPF Pass" / "⚠ DKIM Fail".
  # Icon buckets mirror auth_badge_classes: ✓ only for a clean pass.
  def auth_badge_label(mechanism, verdict)
    icon = verdict == "pass" ? "✓" : "⚠"
    "#{icon} #{mechanism.upcase} #{(verdict || "none").capitalize}"
  end

  # Human labels for IMAP flags on the message page ("\Seen" reads like a
  # protocol dump). Standard system flags and the common client keywords
  # get proper names; anything else shows minus its \ or $ sigil. The raw
  # flag stays in the pill's title.
  FLAG_LABELS = {
    "\\Seen" => "Read", "\\Answered" => "Replied", "\\Flagged" => "★ Flagged",
    "\\Deleted" => "Deleted", "\\Draft" => "Draft", "\\Recent" => "Recent",
    "$Forwarded" => "Forwarded", "$Junk" => "Junk", "$NotJunk" => "Not junk"
  }.freeze

  def flag_pill_label(flag)
    FLAG_LABELS.fetch(flag) { flag.delete_prefix("\\").delete_prefix("$") }
  end

  # Same pill palette as the other badges: amber for the attention-seeker,
  # red for the doomed, neutral slate for the rest.
  def flag_pill_classes(flag)
    case flag
    when "\\Flagged"          then "bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-400"
    when "\\Deleted", "$Junk" then "bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-400"
    else                           "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
    end
  end

  # rspamd score for the footer: "score / threshold — action", degrading to
  # just the score when the threshold or action weren't recorded.
  def spam_score_label(message)
    label = if message.spam_threshold.present?
      "#{message.spam_score} / #{message.spam_threshold}"
    else
      message.spam_score.to_s
    end
    label += " — #{message.spam_action}" if message.spam_action.present?
    label
  end

  # Green like a passing auth badge when rspamd decided "no action";
  # the neutral slate pill otherwise.
  def spam_badge_classes(message)
    spam_clean?(message) ? "bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-400" : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
  end

  def spam_clean?(message) = message.spam_action == "no action"
end
