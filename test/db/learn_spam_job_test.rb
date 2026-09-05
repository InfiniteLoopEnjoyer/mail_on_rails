# frozen_string_literal: true

require_relative "test_helper"
require "fake_rspamd"

class LearnSpamJobTest < DbSuite::TestCase
  RAW = "From: spammer@remote.test\r\nTo: bob@example.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def setup
    super
    enqueued.clear
    @saved_addr = ENV["SMTP_RSPAMD_CONTROLLER_ADDR"]
  end

  def teardown
    ENV["SMTP_RSPAMD_CONTROLLER_ADDR"] = @saved_addr
    ENV.delete("SMTP_RSPAMD_CONTROLLER_ADDR") if @saved_addr.nil?
  end

  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "bob@example.test",
                                                   password: "a-long-test-password")
  end

  def spam_message
    @spam_message ||= MailOnRails::EmailMessage.deliver_raw(account.junk_mailbox, RAW)
  end

  def enqueued
    MailOnRails::LearnSpamJob.queue_adapter.enqueued_jobs
  end

  def perform(message_id: spam_message.id, content_id: spam_message.email_object_id, klass: "spam")
    MailOnRails::LearnSpamJob.perform_now(message_id, content_id, account.id, klass)
  end

  def with_controller(addr)
    ENV["SMTP_RSPAMD_CONTROLLER_ADDR"] = addr
    yield
  end

  test "does nothing until a controller address is configured" do
    ENV.delete("SMTP_RSPAMD_CONTROLLER_ADDR")
    FakeRspamd.serving("no action") do |addr, fake|
      # addr is deliberately not configured
      perform
      assert_empty fake.requests, "must not call rspamd (#{addr})"
    end
  end

  test "posts the message bytes to the learn endpoint for its class" do
    FakeRspamd.serving("no action") do |addr, fake|
      with_controller(addr) do
        perform(klass: "spam")
        perform(klass: "ham")
      end
      assert_equal [ "POST /learnspam HTTP/1.1\r\n", "POST /learnham HTTP/1.1\r\n" ], fake.requests.map { |r| r[:line] }
      assert_equal [ spam_message.raw, spam_message.raw ], fake.requests.map { |r| r[:body] }
    end
    assert_empty enqueued, "nothing to retry"
  end

  test "a repeat learn of the same class is success" do
    FakeRspamd.serving("no action", learn_status: 404) do |addr|
      with_controller(addr) { perform }
    end
    assert_empty enqueued
  end

  test "a refusal is logged and not retried" do
    FakeRspamd.serving("no action", learn_status: 403) do |addr|
      with_controller(addr) { perform }
    end
    assert_empty enqueued
  end

  test "an unreachable controller is retried" do
    closed = TCPServer.new("127.0.0.1", 0)
    addr = "127.0.0.1:#{closed.addr[1]}"
    closed.close

    with_controller(addr) { perform }
    assert_equal [ MailOnRails::LearnSpamJob ], enqueued.map { |job| job[:job] }
  end

  test "finds the message by its content id after it was moved again" do
    moved = spam_message.move_to!(account.inbox)
    FakeRspamd.serving("no action") do |addr, fake|
      with_controller(addr) { perform(message_id: spam_message.id, content_id: moved.email_object_id) }
      assert_equal [ moved.raw ], fake.requests.map { |r| r[:body] }
    end
  end

  test "a message that is gone is nothing to learn from" do
    FakeRspamd.serving("no action") do |addr, fake|
      with_controller(addr) { perform(message_id: 0, content_id: "Enothing") }
      assert_empty fake.requests
    end
  end
end
