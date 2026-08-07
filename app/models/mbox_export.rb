# A mailbox serialized as an mbox file (RFC 4155 appendix A), the lingua
# franca every mail client and archiver imports. Enumerable and lazy - one
# message in memory at a time - so the controller can stream it as the
# response body of an arbitrarily large folder.
#
# Dialect: mboxrd. Body lines matching /\A>*From / are quoted with one
# more ">" so an embedded "From " can never be mistaken for a message
# separator, and the quoting is reversible (unlike mboxo, which loses
# ">From " lines). Line endings are converted to bare LF, the Unix
# convention mbox inherited.
class MboxExport
  include Enumerable

  def initialize(mailbox)
    @mailbox = mailbox
  end

  def filename
    "#{@mailbox.name.gsub(/[^\w\-]+/, "-")}.mbox"
  end

  # find_each batches by primary key, which follows delivery order - the
  # natural order of an mbox file.
  def each
    return to_enum(:each) unless block_given?

    @mailbox.email_messages.find_each do |message|
      yield from_line(message)
      yield body(message)
    end
  end

  private

  # The "From " separator: envelope sender and asctime-format date. The
  # sender is informational; anything that could break the line (spaces,
  # control characters, or no sender at all) falls back to the
  # conventional MAILER-DAEMON.
  def from_line(message)
    sender = message.from_address.to_s
    sender = "MAILER-DAEMON" unless sender.match?(/\A[[:graph:]]+\z/)
    "From #{sender} #{(message.internal_date || Time.current).utc.strftime("%a %b %e %H:%M:%S %Y")}\n"
  end

  def body(message)
    text = message.raw.gsub("\r\n", "\n")
    text << "\n" unless text.end_with?("\n")
    # mboxrd quoting, then a blank line to close the message.
    text.gsub(/^(>*From )/, ">\\1") << "\n"
  end
end
