module ApplicationHelper
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
