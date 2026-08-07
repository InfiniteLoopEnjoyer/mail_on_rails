require "test_helper"
require "mail_on_rails/smtp/send_quota"

# The vacation autoresponder and its loop protections (RFC 3834): answer
# real correspondence once per sender per window, never answer bounces,
# automatic mail, or list traffic, and pay for every reply out of the
# account's send quota.
class VacationResponderTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "away@example.com", password: "secret123",
                                    vacation_enabled: true, vacation_subject: "Out of office",
                                    vacation_body: "Back on Monday.")
  end

  def inbound(from: "friend@remote.test", headers: {}, reply_to: nil, message_id: "<orig@remote.test>")
    mail = Mail.new
    mail.from = from
    mail.reply_to = reply_to if reply_to
    mail.to = @account.email
    mail.subject = "checking in"
    mail.message_id = message_id
    mail.body = "hello"
    headers.each { |name, value| mail.header[name] = value }
    mail
  end

  def respond(mail = inbound, return_path: "friend@remote.test", quota: nil)
    VacationResponder.deliver_if_due(@account, mail, return_path: return_path, quota: quota)
  end

  test "replies to a remote sender through the outbound queue, marked auto-replied" do
    assert respond

    queued = SmtpOutboundMessage.sole
    assert_equal @account.email, queued.mail_from
    assert_equal "friend@remote.test", queued.recipient

    reply = Mail.read_from_string(queued.data)
    assert_equal "Out of office", reply.subject
    assert_includes reply.body.decoded, "Back on Monday."
    assert_equal "auto-replied", reply.header["Auto-Submitted"].value
    assert_equal "orig@remote.test", Array(reply.in_reply_to).first
  end

  test "a local sender gets the reply straight into their inbox" do
    local = EmailAccount.create!(email: "colleague@example.com", password: "secret123")

    assert respond(inbound(from: "colleague@example.com"), return_path: "colleague@example.com")

    message = local.inbox.email_messages.sole
    assert_equal "Out of office", message.subject
    assert_equal 0, SmtpOutboundMessage.count
  end

  test "each sender is answered once per window" do
    assert respond
    assert_not respond, "the second message inside the window must go unanswered"
    assert_equal 1, SmtpOutboundMessage.count

    travel(VacationResponder::REPLY_WINDOW + 1.minute) do
      assert respond, "a fresh window earns a fresh reply"
    end
    assert_equal 2, SmtpOutboundMessage.count
  end

  test "a disabled or out-of-range vacation stays silent" do
    @account.update!(vacation_enabled: false)
    assert_not respond

    @account.update!(vacation_enabled: true, vacation_starts_on: Date.tomorrow)
    assert_not respond

    @account.update!(vacation_starts_on: nil, vacation_ends_on: Date.yesterday)
    assert_not respond
    assert_equal 0, SmtpOutboundMessage.count
  end

  test "bounces and the null sender are never answered" do
    assert_not respond(inbound, return_path: "")
    assert_not respond(inbound, return_path: "<>")
    assert_not respond(inbound, return_path: "MAILER-DAEMON@remote.test")
    assert_not respond(inbound, return_path: "postmaster@remote.test")
    assert_equal 0, SmtpOutboundMessage.count
  end

  test "automatic and list mail is never answered" do
    assert_not respond(inbound(headers: { "Auto-Submitted" => "auto-generated" }))
    assert_not respond(inbound(headers: { "Precedence" => "bulk" }))
    assert_not respond(inbound(headers: { "X-Auto-Response-Suppress" => "OOF" }))
    assert_not respond(inbound(headers: { "List-Id" => "<dev.lists.remote.test>" }))
    assert_equal 0, SmtpOutboundMessage.count

    assert respond(inbound(headers: { "Auto-Submitted" => "no" })), "Auto-Submitted: no is human mail"
  end

  test "the account never answers itself and honors Reply-To" do
    assert_not respond(inbound(from: @account.email), return_path: @account.email)

    @account.email_aliases.create!(email: "me@example.com")
    assert_not respond(inbound(from: "me@example.com"), return_path: "me@example.com")

    assert respond(inbound(reply_to: "replies@remote.test"))
    assert_equal "replies@remote.test", SmtpOutboundMessage.sole.recipient
  end

  test "a reply consumes a send quota slot and an exhausted quota skips the reply" do
    quota = MailOnRails::Smtp::SendQuota.new(limit: 1, window: 3600)
    assert respond(inbound, quota: quota)

    travel(VacationResponder::REPLY_WINDOW + 1.minute) do
      assert_not respond(inbound, quota: quota), "an empty quota must silence the responder"
    end
    assert_equal 1, SmtpOutboundMessage.count
  end

  test "a missing subject falls back to an Automatic reply marker" do
    @account.update!(vacation_subject: nil)
    assert respond

    assert_equal "Automatic reply: checking in", Mail.read_from_string(SmtpOutboundMessage.sole.data).subject
  end
end
