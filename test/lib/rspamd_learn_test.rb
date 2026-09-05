# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/rspamd_analyzer"
require "fake_rspamd"

# RspamdAnalyzer.learn's contract: a four-way verdict, never an exception,
# aimed at the controller worker (its own address) with the Password
# header, so the job that drives it can decide between retrying and
# giving up.
class RspamdLearnTest < Minitest::Test
  RAW = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def learn(addr, klass = "spam")
    MailOnRails::RspamdAnalyzer.learn(RAW, klass, addr: addr, timeout: 5)
  end

  def with_env(values)
    saved = values.keys.to_h { |key| [ key, ENV[key] ] }
    values.each { |key, value| ENV[key] = value }
    yield
  ensure
    saved.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end

  def test_learning_is_off_until_the_controller_address_is_set
    with_env("SMTP_RSPAMD_CONTROLLER_ADDR" => nil) do
      assert_not MailOnRails::RspamdAnalyzer.learning_enabled?
    end
    with_env("SMTP_RSPAMD_CONTROLLER_ADDR" => "127.0.0.1:11334") do
      assert MailOnRails::RspamdAnalyzer.learning_enabled?
      assert_equal "127.0.0.1:11334", MailOnRails::RspamdAnalyzer.controller_addr
    end
  end

  def test_learns_spam_and_ham_on_their_own_endpoints_with_the_password
    with_env("SMTP_RSPAMD_PASSWORD" => "hunter2") do
      FakeRspamd.serving("no action") do |addr, fake|
        assert_equal :ok, learn(addr, "spam")
        assert_equal :ok, learn(addr, "ham")

        assert_equal [ "POST /learnspam HTTP/1.1\r\n", "POST /learnham HTTP/1.1\r\n" ], fake.requests.map { |r| r[:line] }
        assert_equal [ RAW, RAW ], fake.requests.map { |r| r[:body] }
        assert_equal [ "hunter2", "hunter2" ], fake.requests.map { |r| r[:headers]["password"] }
      end
    end
  end

  def test_no_password_header_without_a_password
    with_env("SMTP_RSPAMD_PASSWORD" => nil) do
      FakeRspamd.serving("no action") do |addr, fake|
        learn(addr)
        assert_nil fake.requests.first[:headers]["password"]
      end
    end
  end

  def test_a_repeat_of_the_same_class_is_already_learned
    FakeRspamd.serving("no action", learn_status: 404) do |addr|
      assert_equal :already_learned, learn(addr)
    end
  end

  def test_other_client_errors_are_rejected_not_retried
    FakeRspamd.serving("no action", learn_status: 403) do |addr|
      assert_equal :rejected, learn(addr)
    end
  end

  def test_server_errors_are_unavailable
    FakeRspamd.serving("no action", learn_status: 500) do |addr|
      assert_equal :unavailable, learn(addr)
    end
  end

  def test_refused_connection_is_unavailable
    closed = TCPServer.new("127.0.0.1", 0)
    addr = "127.0.0.1:#{closed.addr[1]}"
    closed.close
    assert_equal :unavailable, learn(addr)
  end

  def test_unknown_class_is_a_programming_error
    assert_raises(KeyError) { learn("127.0.0.1:1", "maybe") }
  end
end
