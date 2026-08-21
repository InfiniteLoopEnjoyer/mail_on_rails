# frozen_string_literal: true

require "test_helper"
require "active_job"

require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ingest_unsubscribe_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/deliver_smtp_outbound_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# The List-Unsubscribe pipeline (RFC 2369/8058): header injection before
# signing for outbound list mail, the signed token, sender-scoped
# suppression, and the mailto ingestion path.
class UnsubscribeTest < DbSuite::TestCase
  SENDER = "news@example.test"
  RECIPIENT = "reader@remote.test"

  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
    MailOnRails::Domain.create!(name: "example.test")
  end

  def queue_message(data, mail_from: SENDER, recipient: RECIPIENT)
    MailOnRails::SmtpOutboundMessage.create!(mail_from: mail_from, recipient: recipient,
                                             data: data, next_attempt_at: Time.current)
  end

  LIST_MAIL = "From: news@example.test\r\nList-ID: <news.example.test>\r\nSubject: weekly\r\n\r\nhello\r\n"
  PERSONAL_MAIL = "From: news@example.test\r\nSubject: hi\r\n\r\nhello\r\n"

  def inject(data, message, web_host: "mail.example.test")
    previous = ENV["MAIL_ON_RAILS_WEB_HOST"]
    web_host ? ENV["MAIL_ON_RAILS_WEB_HOST"] = web_host : ENV.delete("MAIL_ON_RAILS_WEB_HOST")
    MailOnRails::OutboundDeliverer.new.send(:inject_list_unsubscribe, data, message)
  ensure
    previous ? ENV["MAIL_ON_RAILS_WEB_HOST"] = previous : ENV.delete("MAIL_ON_RAILS_WEB_HOST")
  end

  test "token round-trips and rejects tampering" do
    token = MailOnRails::UnsubscribeToken.generate(recipient: RECIPIENT, sender: SENDER)
    data = MailOnRails::UnsubscribeToken.verify(token)

    assert_equal RECIPIENT, data[:recipient]
    assert_equal SENDER, data[:sender]
    assert_nil MailOnRails::UnsubscribeToken.verify(token.sub(/\A../, "xx"))
    assert_nil MailOnRails::UnsubscribeToken.verify("garbage")
    assert_nil MailOnRails::UnsubscribeToken.verify(nil)
  end

  test "list mail gets one-click headers injected, DKIM-signable" do
    message = queue_message(LIST_MAIL)
    result = inject(LIST_MAIL, message)

    assert_match(%r{^List-Unsubscribe: <https://mail\.example\.test/unsubscribe/[^>]+>, <mailto:unsubscribe@example\.test\?subject=unsubscribe%3A[^>]+>\r\n}, result)
    assert_match(/^List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n/, result)

    token = CGI.unescape(result[%r{/unsubscribe/([^>]+)>}, 1])
    data = MailOnRails::UnsubscribeToken.verify(token)
    assert_equal RECIPIENT, data[:recipient], "the injected token must bind the actual recipient"
  end

  test "without a web host the mailto rides alone and one-click is not claimed" do
    message = queue_message(LIST_MAIL)
    result = inject(LIST_MAIL, message, web_host: nil)

    assert_match(/^List-Unsubscribe: <mailto:/, result)
    refute_match(/^List-Unsubscribe-Post:/, result)
  end

  test "personal mail, foreign domains, existing headers, and the opt-out are left alone" do
    message = queue_message(PERSONAL_MAIL)
    assert_equal PERSONAL_MAIL, inject(PERSONAL_MAIL, message), "no List-ID, no injection"

    foreign = queue_message(LIST_MAIL, mail_from: "news@unhosted.test")
    assert_equal LIST_MAIL, inject(LIST_MAIL, foreign), "unhosted sender domain, no injection"

    own = LIST_MAIL.sub("Subject:", "List-Unsubscribe: <mailto:own@example.test>\r\nSubject:")
    message = queue_message(own)
    assert_equal own, inject(own, message), "a composer-provided header wins"

    MailOnRails::Settings.overrides = { smtp_list_unsubscribe: false }
    message = queue_message(LIST_MAIL)
    assert_equal LIST_MAIL, inject(LIST_MAIL, message)
  ensure
    MailOnRails::Settings.reset!
  end

  test "suppression is sender-scoped for unsubscribes, global for complaints" do
    MailOnRails::SuppressedRecipient.record_unsubscribe!(RECIPIENT, sender: SENDER)

    assert MailOnRails::SuppressedRecipient.suppressed?(RECIPIENT, sender: SENDER)
    assert_not MailOnRails::SuppressedRecipient.suppressed?(RECIPIENT, sender: "other@example.test"),
               "an unsubscribe from one sender must not block another"
    assert_not MailOnRails::SuppressedRecipient.suppressed?(RECIPIENT), "no sender given - only global rows count"

    MailOnRails::SuppressedRecipient.record_complaint!(RECIPIENT)
    assert MailOnRails::SuppressedRecipient.suppressed?(RECIPIENT, sender: "other@example.test"),
           "an FBL complaint suppresses every sender"
  end

  test "outbound delivery honors a sender-scoped suppression" do
    MailOnRails::SuppressedRecipient.record_unsubscribe!(RECIPIENT, sender: SENDER)
    suppressed = queue_message(LIST_MAIL)
    other = queue_message(LIST_MAIL, mail_from: "other@example.test")

    singleton = MailOnRails::OutboundDeliverer.singleton_class
    original = MailOnRails::OutboundDeliverer.method(:deliver)
    attempted = []
    singleton.define_method(:deliver) { |message| attempted << message.recipient; :delivered }
    begin
      MailOnRails::DeliverSmtpOutboundJob.new.perform
    ensure
      singleton.define_method(:deliver, original)
    end

    assert_predicate suppressed.reload, :failed?
    assert_match(/unsubscribed/, suppressed.last_error)
    assert_predicate other.reload, :sent?, "the same recipient still gets other senders' mail"
  end

  test "mailto ingestion honors only a valid token" do
    token = MailOnRails::UnsubscribeToken.generate(recipient: RECIPIENT, sender: SENDER)
    message = Struct.new(:id, :subject, :from_address).new(1, "unsubscribe:#{token}", RECIPIENT)

    MailOnRails::IngestUnsubscribeJob.new.perform(message)
    assert MailOnRails::SuppressedRecipient.suppressed?(RECIPIENT, sender: SENDER)

    MailOnRails::SuppressedRecipient.delete_all
    forged = Struct.new(:id, :subject, :from_address).new(2, "unsubscribe:not-a-token", RECIPIENT)
    MailOnRails::IngestUnsubscribeJob.new.perform(forged)
    assert_equal 0, MailOnRails::SuppressedRecipient.count

    bare = Struct.new(:id, :subject, :from_address).new(3, "please remove me", RECIPIENT)
    MailOnRails::IngestUnsubscribeJob.new.perform(bare)
    assert_equal 0, MailOnRails::SuppressedRecipient.count
  end

  test "a mailing-list account gets List-ID stamped, pulling in the unsubscribe headers" do
    MailOnRails::EmailAccount.create!(email: SENDER, name: "News", password: "secret-123",
                                      mailing_list: true)
    message = queue_message(PERSONAL_MAIL)

    with_list_id = MailOnRails::OutboundDeliverer.new.send(:inject_list_id, PERSONAL_MAIL, message)
    assert_match(/\AList-ID: <news\.example\.test>\r\n/, with_list_id)

    result = inject(with_list_id, message)
    assert_match(/^List-Unsubscribe: /, result, "the stamped List-ID must trigger the one-click injection")

    # A composer-provided List-ID wins over the derived one.
    assert_equal LIST_MAIL, MailOnRails::OutboundDeliverer.new.send(:inject_list_id, LIST_MAIL, message)
  end

  test "an unflagged account never gets a List-ID stamped" do
    MailOnRails::EmailAccount.create!(email: SENDER, name: "News", password: "secret-123")
    message = queue_message(PERSONAL_MAIL)

    assert_equal PERSONAL_MAIL, MailOnRails::OutboundDeliverer.new.send(:inject_list_id, PERSONAL_MAIL, message)
  end

  test "domain creation provisions the unsubscribe account and routing" do
    assert MailOnRails::EmailAccount.exists?(email: "unsubscribe@example.test")
    assert_equal MailOnRails::IngestUnsubscribeJob,
                 MailOnRails::Domain.ingestion_job_for("unsubscribe@example.test")
    assert_nil MailOnRails::Domain.ingestion_job_for("unsubscribe@unhosted.test")
  end
end
