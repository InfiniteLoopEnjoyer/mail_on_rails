# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/deliver_smtp_outbound_job", __dir__)

# Per-destination outbound pacing (smtp_outbound_domain_batch): at most N
# delivery attempts per destination domain per queue run, and a transient
# failure parks the domain's remaining messages for the rest of the run -
# large ISPs rate-limit by source IP, so a burst or a "slow down" must
# not be answered with more connections. Plus the pre-signing
# Message-ID/Date injection on the deliverer.
class OutboundPacingTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
  end

  def teardown
    MailOnRails::Settings.reset!
  end

  def queue_message(recipient)
    MailOnRails::SmtpOutboundMessage.create!(mail_from: "sender@example.test", recipient: recipient,
                                             data: "From: sender@example.test\r\n\r\nhi",
                                             next_attempt_at: Time.current)
  end

  # Replaces OutboundDeliverer.deliver with +stub+ for the block; the
  # stub's return/raise drives the job's bookkeeping.
  def with_delivery_stub(stub)
    singleton = MailOnRails::OutboundDeliverer.singleton_class
    original = MailOnRails::OutboundDeliverer.method(:deliver)
    singleton.define_method(:deliver) { |message| stub.call(message) }
    yield
  ensure
    singleton.define_method(:deliver, original)
  end

  test "attempts per destination domain are capped per run" do
    MailOnRails::Settings.overrides = { smtp_outbound_domain_batch: 2 }
    4.times { |i| queue_message("user#{i}@busy.test") }
    queue_message("other@elsewhere.test")

    attempted = []
    with_delivery_stub(->(message) { attempted << message.recipient; :delivered }) do
      MailOnRails::DeliverSmtpOutboundJob.new.perform
    end

    assert_equal 2, attempted.count { |r| r.end_with?("@busy.test") },
                 "only smtp_outbound_domain_batch messages per domain per run"
    assert_includes attempted, "other@elsewhere.test", "other domains must not be starved"
    assert_equal 2, MailOnRails::SmtpOutboundMessage.pending.count,
                 "skipped rows stay pending and unclaimed for the next run"
  end

  test "a transient failure parks the domain for the rest of the run" do
    MailOnRails::Settings.overrides = { smtp_outbound_domain_batch: 10 }
    3.times { |i| queue_message("user#{i}@limiting.test") }
    queue_message("other@elsewhere.test")

    attempted = []
    stub = lambda do |message|
      attempted << message.recipient
      if message.recipient.end_with?("@limiting.test")
        raise MailOnRails::OutboundDeliverer::TransientError, "421 4.7.0 slow down"
      end

      :delivered
    end
    with_delivery_stub(stub) { MailOnRails::DeliverSmtpOutboundJob.new.perform }

    assert_equal 1, attempted.count { |r| r.end_with?("@limiting.test") },
                 "after a 4xx the domain's remaining messages wait for the next run"
    assert_includes attempted, "other@elsewhere.test"
  end

  test "batch 0 disables pacing" do
    MailOnRails::Settings.overrides = { smtp_outbound_domain_batch: 0 }
    3.times { |i| queue_message("user#{i}@busy.test") }

    attempted = []
    with_delivery_stub(->(message) { attempted << message.recipient; :delivered }) do
      MailOnRails::DeliverSmtpOutboundJob.new.perform
    end

    assert_equal 3, attempted.size
  end

  # -- pre-signing header injection ----------------------------------------

  test "missing Message-ID and Date are injected, stable across attempts" do
    message = queue_message("user@remote.test")
    deliverer = MailOnRails::OutboundDeliverer.new
    data = MailOnRails::Smtp::OutboundData.canonicalize(message.data)

    first = deliverer.send(:ensure_required_headers, data, message)
    second = deliverer.send(:ensure_required_headers, data, message)

    assert_match(/^Message-ID: <mor-#{message.id}-\h{16}@[^>]+>\r\n/, first)
    assert_match(/^Date: .+\r\n/, first)
    assert_equal first, second, "a retry must carry the same injected headers"
  end

  test "present headers are left alone" do
    message = queue_message("user@remote.test")
    data = "Message-ID: <given@client.test>\r\nDate: Mon, 17 Aug 2026 10:00:00 +0000\r\n" \
           "From: sender@example.test\r\n\r\nhi"

    result = MailOnRails::OutboundDeliverer.new.send(:ensure_required_headers, data, message)

    assert_equal data, result
  end
end
