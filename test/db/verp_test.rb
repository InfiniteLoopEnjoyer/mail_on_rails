# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ingest_bounce_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# VERP end to end: signed bounce+ return paths on outbound list mail,
# edge acceptance of the sub-addresses, and hard-DSN-only suppression on
# what comes back.
class VerpTest < DbSuite::TestCase
  SENDER = "news@example.test"
  RECIPIENT = "reader@remote.test"
  LIST_MAIL = "From: news@example.test\r\nList-ID: <news.example.test>\r\nSubject: weekly\r\n\r\nhello\r\n"
  PERSONAL_MAIL = "From: news@example.test\r\nSubject: hi\r\n\r\nhello\r\n"

  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    MailOnRails::Domain.create!(name: "example.test")
  end

  def queue_message(data = LIST_MAIL)
    MailOnRails::SmtpOutboundMessage.create!(mail_from: SENDER, recipient: RECIPIENT,
                                             data: data, next_attempt_at: Time.current)
  end

  test "encode/valid?/decode round-trip; tampering and unknown rows fail closed" do
    message = queue_message
    address = MailOnRails::VerpAddress.encode(message)

    assert_match(/\Abounce\+m#{message.id}-\h{12}@example\.test\z/, address)
    assert_operator address.split("@").first.length, :<=, 64, "the local part must fit RFC 5321's budget"
    assert MailOnRails::VerpAddress.valid?(address)
    assert_equal message, MailOnRails::VerpAddress.decode(address)

    tampered = address.sub(/-\h{12}@/) { |m| m.tr("0-9a-f", "1-9a-f0") }
    assert_not MailOnRails::VerpAddress.valid?(tampered)
    assert_nil MailOnRails::VerpAddress.decode(tampered)
    assert_not MailOnRails::VerpAddress.valid?("bounce+mX-abc@example.test")

    message.destroy!
    assert MailOnRails::VerpAddress.valid?(address), "validity is pure crypto"
    assert_nil MailOnRails::VerpAddress.decode(address), "a pruned row decodes to nothing"
  end

  test "list mail gets a VERP return path; personal mail and opt-out keep theirs" do
    deliverer = MailOnRails::OutboundDeliverer.new
    message = queue_message

    verp = deliverer.send(:verp_return_path, message, LIST_MAIL)
    assert_equal MailOnRails::VerpAddress.encode(message), verp

    assert_nil deliverer.send(:verp_return_path, message, PERSONAL_MAIL), "no List-ID, no rewrite"

    unhosted = MailOnRails::SmtpOutboundMessage.create!(mail_from: "news@unhosted.test", recipient: RECIPIENT,
                                                        data: LIST_MAIL, next_attempt_at: Time.current)
    assert_nil deliverer.send(:verp_return_path, unhosted, LIST_MAIL), "no bounce@ account to receive replies"

    MailOnRails::Settings.overrides = { smtp_verp: false }
    assert_nil deliverer.send(:verp_return_path, message, LIST_MAIL)
  ensure
    MailOnRails::Settings.reset!
  end

  test "the envelope sender override carries the ESMTP params" do
    message = queue_message
    address = MailOnRails::VerpAddress.encode(message)
    deliverer = MailOnRails::OutboundDeliverer.new

    assert_equal address, deliverer.send(:envelope_sender, message, propagate_dsn: false, address: address)
    assert_equal SENDER, deliverer.send(:envelope_sender, message, propagate_dsn: false, address: nil)

    message.update!(requiretls: true)
    with_params = deliverer.send(:envelope_sender, message, propagate_dsn: false, address: address)
    assert_kind_of Net::SMTP::Address, with_params
    assert_equal address, with_params.address
  end

  # An edge-stamped bounce as it lands in the bounce@ account.
  def bounce_raw(verp_address, status: "5.1.1", action: "failed", dsn: true)
    body = if dsn
      <<~RAW
        Content-Type: multipart/report; report-type=delivery-status; boundary="b"

        --b
        Content-Type: text/plain

        Delivery failed.
        --b
        Content-Type: message/delivery-status

        Reporting-MTA: dns; mx.remote.test
        Action: #{action}
        Status: #{status}

        --b--
      RAW
    else
      "Content-Type: text/plain\n\nI am out of the office until Monday.\n"
    end
    "Return-Path: <>\nX-Original-To: #{verp_address}\nFrom: mailer-daemon@remote.test\n" \
      "Subject: delivery status\n#{body}"
  end

  def ingest(raw)
    message = Struct.new(:id, :raw).new(1, raw)
    MailOnRails::IngestBounceJob.new.perform(message)
  end

  test "a hard 5.x.x DSN suppresses the recipient for that sender only" do
    message = queue_message
    ingest(bounce_raw(MailOnRails::VerpAddress.encode(message)))

    assert MailOnRails::SuppressedRecipient.suppressed?(RECIPIENT, sender: SENDER)
    assert_not MailOnRails::SuppressedRecipient.suppressed?(RECIPIENT, sender: "other@example.test")
    record = MailOnRails::SuppressedRecipient.last
    assert_equal "hard-bounce", record.feedback_type
    assert_equal "mx.remote.test", record.reporter
  end

  test "transient DSNs, autoreplies, and forged addresses suppress nothing" do
    message = queue_message
    address = MailOnRails::VerpAddress.encode(message)

    ingest(bounce_raw(address, status: "4.4.1", action: "delayed"))
    ingest(bounce_raw(address, dsn: false)) # vacation autoreply to the return path
    ingest(bounce_raw(address.sub(/-\h{12}@/, "-000000000000@")))

    assert_equal 0, MailOnRails::SuppressedRecipient.count
  end

  test "domain creation provisions bounce@ and its ingestion routing" do
    assert MailOnRails::EmailAccount.exists?(email: "bounce@example.test")
    assert_equal MailOnRails::IngestBounceJob, MailOnRails::Domain.ingestion_job_for("bounce@example.test")
  end
end
