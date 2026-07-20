# Global backstop against catastrophic-backtracking (ReDoS) regexes.
#
# Our hand-written protocol/MIME regexes were audited and are linear, and
# Ruby 3.2+ memoization already neutralizes most classic ReDoS. This mainly
# insures against regexes we don't control - the Mail gem parsing untrusted
# inbound messages - and against future edits.
#
# The value is deliberately generous: legitimate regexes (including large
# message parsing) finish in well under a second, so only pathological
# backtracking trips it. Set once at boot; the global applies to every
# thread, including the SMTP/IMAP server threads.
Regexp.timeout = Float(ENV.fetch("MAIL_ON_RAILS_REGEXP_TIMEOUT", 3.0))
