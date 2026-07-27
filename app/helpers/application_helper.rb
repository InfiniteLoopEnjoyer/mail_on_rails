module ApplicationHelper
  # Sets the <title> as "Mail on Rails - <subtitle>".
  def page_title(subtitle)
    content_for :title, "Mail on Rails - #{subtitle}"
  end

  # Section predicates for the sidebar nav. Mailboxes is the child of Domains
  # and owns the whole account/mailbox/message drill-down.
  def domains_section?   = controller_name == "domains"
  def users_section?     = controller_name == "users"
  def settings_section?  = controller_name == "settings"
  def security_section?  = controller_name == "security" || controller_path.start_with?("two_factor/")
  def mailboxes_section? = %w[email_accounts mailboxes email_messages].include?(controller_name)

  # Sidebar link classes; child items are indented + a shade lighter to read
  # as nested. Keep every class literal so Tailwind's scanner sees them.
  def nav_link_classes(active, child: false)
    base  = child ? "block rounded-md py-1.5 pr-3 pl-9 text-sm" \
                  : "block rounded-md px-3 py-2 text-sm font-medium"
    state =
      if active
        "bg-accent/10 font-medium text-accent"
      elsif child
        "text-slate-400 hover:bg-slate-50 hover:text-slate-600"
      else
        "text-slate-500 hover:bg-slate-50 hover:text-slate-800"
      end
    "#{base} #{state}"
  end

  # Tailwind bg/text classes for a sender-auth verdict badge (spf/dkim/dmarc),
  # bucketed by how the mechanism landed. Used by the received-message
  # analysis footer.
  def auth_badge_classes(verdict)
    case verdict
    when "pass"                             then "bg-green-100 text-green-700"
    when "fail", "permerror", "temperror"   then "bg-red-100 text-red-700"
    when "softfail", "neutral"              then "bg-amber-100 text-amber-700"
    else                                         "bg-slate-100 text-slate-600"
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
end
