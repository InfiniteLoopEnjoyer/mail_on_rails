# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/deliver_smtp_outbound_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# One message's delivery raising something nobody planned for - the
# destination's DNS, its server and the message itself are all outside
# input - is that message's failure: retried like any transient one,
# bounced when its attempts run out, and never the end of the queue run
# for the messages behind it.
class OutboundJobIsolationTest < DbSuite::TestCase
  Message = MailOnRails::SmtpOutboundMessage

  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
  end

  def teardown
    MailOnRails::Settings.reset!
  end

  def queue_message(recipient, **attributes)
    Message.create!(mail_from: "carol@example.test", recipient: recipient,
                    data: "From: carol@example.test\r\n\r\nhi", next_attempt_at: Time.current, **attributes)
  end

  def with_delivery_stub(stub)
    singleton = MailOnRails::OutboundDeliverer.singleton_class
    original = MailOnRails::OutboundDeliverer.method(:deliver)
    singleton.define_method(:deliver) { |message| stub.call(message) }
    yield
  ensure
    singleton.define_method(:deliver, original)
  end

  # Delivery to hostile.test raises what a malformed TLSA record used to
  # raise out of the DNS layer; everything else is delivered.
  def hostile_stub(attempted)
    lambda do |message|
      attempted << message.recipient
      raise ArgumentError, "data with invalid value: deadbeef" if message.recipient.end_with?("@hostile.test")

      :delivered
    end
  end

  test "an unexpected error is charged to its message and the batch goes on" do
    first = queue_message("a@hostile.test")
    queue_message("b@elsewhere.test")
    queue_message("c@third.test")

    attempted = []
    with_delivery_stub(hostile_stub(attempted)) { MailOnRails::DeliverSmtpOutboundJob.new.perform }

    assert_equal %w[a@hostile.test b@elsewhere.test c@third.test], attempted
    assert_equal 2, Message.sent.count, "the messages queued behind the failure were still delivered"

    first.reload
    assert_predicate first, :pending?
    assert_equal 1, first.attempts
    assert_equal "ArgumentError: data with invalid value: deadbeef", first.last_error
    assert_operator first.next_attempt_at, :>, Time.current, "retried with backoff, like any transient failure"
  end

  test "it parks the destination for the rest of the run, as a deferral does" do
    MailOnRails::Settings.overrides = { smtp_outbound_domain_batch: 10 }
    3.times { |i| queue_message("user#{i}@hostile.test") }

    attempted = []
    with_delivery_stub(hostile_stub(attempted)) { MailOnRails::DeliverSmtpOutboundJob.new.perform }

    assert_equal [ "user0@hostile.test" ], attempted
  end

  test "on the last attempt it fails the message and bounces it to the sender" do
    account = MailOnRails::EmailAccount.create!(email: "carol@example.test", password: "a-long-test-password")
    doomed = queue_message("a@hostile.test", attempts: Message::MAX_ATTEMPTS - 1)
    queue_message("b@elsewhere.test")

    with_delivery_stub(hostile_stub([])) { MailOnRails::DeliverSmtpOutboundJob.new.perform }

    assert_predicate doomed.reload, :failed?
    assert_equal 1, Message.sent.count
    dsn = account.mailboxes.find_by!(name: "INBOX").email_messages.sole
    assert_match(/a@hostile\.test/, dsn.raw)
    assert_match(/ArgumentError: data with invalid value/, dsn.raw)
  end

  test "even the bookkeeping failing does not stop the run" do
    queue_message("a@hostile.test")
    queue_message("b@elsewhere.test")

    original = Message.instance_method(:record_failure!)
    Message.define_method(:record_failure!) { |*, **| raise ActiveRecord::StatementInvalid, "database is locked" }
    begin
      with_delivery_stub(hostile_stub([])) { MailOnRails::DeliverSmtpOutboundJob.new.perform }
    ensure
      Message.define_method(:record_failure!, original)
    end

    assert_equal 1, Message.sent.count
    assert_equal 1, Message.delivering.count, "left claimed; the stuck sweep returns it to the queue"
  end
end
