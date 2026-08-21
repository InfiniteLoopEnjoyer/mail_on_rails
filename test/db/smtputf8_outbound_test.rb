# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# The delivery side of SMTPUTF8 (RFC 6531): when a message needs the
# extension, how the MAIL parameters carry it, and how internationalized
# domains reach DNS as A-labels.
class Smtputf8OutboundTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
  end

  def queue_message(recipient: "friend@elsewhere.test", mail_from: "user@example.test",
                    data: "From: user@example.test\r\n\r\nhi", smtputf8: false)
    MailOnRails::SmtpOutboundMessage.create!(mail_from: mail_from, recipient: recipient,
                                             data: data, smtputf8: smtputf8,
                                             next_attempt_at: Time.current)
  end

  def deliverer
    @deliverer ||= MailOnRails::OutboundDeliverer.new
  end

  test "idn converts u-labels and passes everything else through" do
    assert_equal "xn--exmple-cua.test", MailOnRails::Idn.to_ascii("exämple.test")
    assert_equal "plain.test", MailOnRails::Idn.to_ascii("plain.test")
    assert_equal "", MailOnRails::Idn.to_ascii(nil)
  end

  test "needs_smtputf8 is driven by the envelope, or by declared+used headers" do
    ascii = queue_message
    assert_not deliverer.send(:needs_smtputf8?, ascii)

    utf8_rcpt = queue_message(recipient: "pelé@elsewhere.test")
    assert deliverer.send(:needs_smtputf8?, utf8_rcpt)

    declared_ascii = queue_message(smtputf8: true)
    assert_not deliverer.send(:needs_smtputf8?, declared_ascii),
               "a declared but all-ASCII message must not be confined to SMTPUTF8 hops"

    declared_utf8_headers = queue_message(smtputf8: true, data: "From: pelé@example.test\r\nSubject: hé\r\n\r\nhi")
    assert deliverer.send(:needs_smtputf8?, declared_utf8_headers)
  end

  test "envelope sender carries the SMTPUTF8 parameter when needed" do
    message = queue_message(recipient: "pelé@elsewhere.test")
    address = deliverer.send(:envelope_sender, message, propagate_dsn: false)

    assert_kind_of Net::SMTP::Address, address
    assert_includes address.parameters, "SMTPUTF8"

    plain = queue_message
    assert_equal plain.mail_from, deliverer.send(:envelope_sender, plain, propagate_dsn: false)
  end
end
