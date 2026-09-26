require "test_helper"
require "mail_on_rails/scram"

# The crypto is pinned to the worked example in RFC 7677 §3:
# user "user", password "pencil", the salts and nonces given there.
class ScramTest < Minitest::Test
  Scram = MailOnRails::Scram

  CLIENT_FIRST_BARE = "n=user,r=rOprNGfwEbeRWgbNEkqO"
  SERVER_FIRST = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," \
                 "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
  CLIENT_FINAL_BARE = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
  PROOF_B64 = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
  SERVER_SIG_B64 = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

  def credentials
    @credentials ||= Scram.derive("pencil", salt: "W22ZaJ0SNY7soEsUEjb6gQ==".unpack1("m0"), iterations: 4096)
  end

  def auth_message
    "#{CLIENT_FIRST_BARE},#{SERVER_FIRST},#{CLIENT_FINAL_BARE}"
  end

  def test_rfc7677_client_proof_verifies
    assert Scram.valid_proof?(credentials[:stored_key], auth_message, PROOF_B64.unpack1("m0"))
  end

  def test_rfc7677_server_signature_matches
    assert_equal SERVER_SIG_B64,
                 [ Scram.server_signature(credentials[:server_key], auth_message) ].pack("m0")
  end

  def test_wrong_password_fails_proof
    wrong = Scram.derive("pencils", salt: "W22ZaJ0SNY7soEsUEjb6gQ==".unpack1("m0"), iterations: 4096)
    refute Scram.valid_proof?(wrong[:stored_key], auth_message, PROOF_B64.unpack1("m0"))
  end

  def test_malformed_proof_length_is_rejected
    refute Scram.valid_proof?(credentials[:stored_key], auth_message, "short")
  end

  # -- client-first parsing (RFC 5802 §5.1, §7) ---------------------------

  def test_split_gs2_parses_the_three_header_flags
    gs2, bare, cb_type, declined = Scram.split_gs2("n,,#{CLIENT_FIRST_BARE}")
    assert_equal [ "n,,", CLIENT_FIRST_BARE, nil, false ], [ gs2, bare, cb_type, declined ]

    _, _, cb_type, declined = Scram.split_gs2("y,,#{CLIENT_FIRST_BARE}")
    assert_equal [ nil, true ], [ cb_type, declined ]

    gs2, bare, cb_type, = Scram.split_gs2("p=tls-exporter,,#{CLIENT_FIRST_BARE}")
    assert_equal [ "p=tls-exporter,,", CLIENT_FIRST_BARE, "tls-exporter" ], [ gs2, bare, cb_type ]

    assert_nil Scram.split_gs2("x,,#{CLIENT_FIRST_BARE}")
  end

  # The reserved "m=" extension: a server that does not understand it
  # MUST fail authentication, not skip past it.
  def test_a_reserved_mext_fails_the_exchange
    assert_nil Scram.split_gs2("n,,m=please-ignore,#{CLIENT_FIRST_BARE}")
    assert_nil Scram.split_gs2("p=tls-exporter,,m=x,#{CLIENT_FIRST_BARE}")
    assert Scram.reject_client_first?(nil, "m=x,n=user,r=abc")
  end

  # An authzid is only ever "myself": a request to act as someone else
  # fails instead of being quietly ignored.
  def test_an_authzid_must_match_the_authcid
    assert_nil Scram.split_gs2("n,a=admin,#{CLIENT_FIRST_BARE}")
    assert_nil Scram.split_gs2("n,a=user,n=other,r=abc"), "an absent authcid cannot match"

    _, bare, = Scram.split_gs2("n,a=user,#{CLIENT_FIRST_BARE}")
    assert_equal CLIENT_FIRST_BARE, bare, "the same identity twice is fine"
    _, bare, = Scram.split_gs2("n,a=,#{CLIENT_FIRST_BARE}")
    assert_equal CLIENT_FIRST_BARE, bare, "an empty a= means 'as myself'"
    _, bare, = Scram.split_gs2("n,a=bob=2Cjr,n=bob=2Cjr,r=abc")
    assert_equal "n=bob=2Cjr,r=abc", bare, "compared in the escaped form both sides use"
  end
end
