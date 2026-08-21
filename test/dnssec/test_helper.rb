# frozen_string_literal: true

# Standalone harness like the other protocol suites: no Rails, just
# dnsruby plus the NSEC3 patches under test.
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

require "minitest/autorun"
require "mail_on_rails/dnssec"

# Minimal stand-in for the Rails-style `test "..."` declaration so suites
# read like Rails ones without pulling in ActiveSupport.
module Minitest
  class Test
    def self.test(name, &block)
      define_method("test_#{name.gsub(/\W+/, '_')}", &block)
    end

    # ActiveSupport::TestCase spelling.
    def assert_not(object, message = nil)
      refute object, message
    end
  end
end

# The RFC 5155 Appendix A zone "example." - the spec's own hash test
# vectors and its complete NSEC3 chain. Every NSEC3 in the appendix
# carries the Opt-Out flag (1 1 12 aabbccdd ...); building the chain with
# flags: 0 gives the no-opt-out variant for asserting :secure proofs.
module Rfc5155Zone
  SALT = "aabbccdd"
  ITERATIONS = 12

  # Appendix A's "H(name)" list, plus the extra hashes worked out in the
  # Appendix B examples (c.x.w and *.x.w from B.1).
  HASHES = {
    "example."       => "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    "a.example."     => "35mthgpgcu1qg68fab165klnsnk3dpvl",
    "ai.example."    => "gjeqe526plbf1g8mklp59enfd789njgi",
    "ns1.example."   => "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
    "ns2.example."   => "q04jkcevqvmu85r014c7dkba38o0ji5r",
    "w.example."     => "k8udemvp1j2f7eg6jebps17vp3n8i58h",
    "*.w.example."   => "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
    "x.w.example."   => "b4um86eghhds6nea196smvmlo4ors995",
    "y.w.example."   => "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
    "x.y.w.example." => "2vptu5timamqttgl4luu9kg21e0aor3s",
    "xx.example."    => "t644ebqk9bibcna874givr6joj62mlhv",
    "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example." => "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
    "c.x.w.example." => "0va5bpr2ou0vk0lbqeeljri88laipsfh",
    "*.x.w.example." => "92pqneegtaue7pjatc3l3qnk738c6v5m"
  }.freeze

  # owner-hash => [next-hash, types] - the zone's NSEC3 chain in hash
  # order, exactly as printed in Appendix A.
  CHAIN = {
    "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" => [ "2t7b4g4vsa5smi47k61mv5bv1a22bojr", "MX DNSKEY NS SOA NSEC3PARAM RRSIG" ],
    "2t7b4g4vsa5smi47k61mv5bv1a22bojr" => [ "2vptu5timamqttgl4luu9kg21e0aor3s", "A RRSIG" ],
    "2vptu5timamqttgl4luu9kg21e0aor3s" => [ "35mthgpgcu1qg68fab165klnsnk3dpvl", "MX RRSIG" ],
    "35mthgpgcu1qg68fab165klnsnk3dpvl" => [ "b4um86eghhds6nea196smvmlo4ors995", "NS DS RRSIG" ],
    "b4um86eghhds6nea196smvmlo4ors995" => [ "gjeqe526plbf1g8mklp59enfd789njgi", "MX RRSIG" ],
    "gjeqe526plbf1g8mklp59enfd789njgi" => [ "ji6neoaepv8b5o6k4ev33abha8ht9fgc", "HINFO A AAAA RRSIG" ],
    "ji6neoaepv8b5o6k4ev33abha8ht9fgc" => [ "k8udemvp1j2f7eg6jebps17vp3n8i58h", "" ],
    "k8udemvp1j2f7eg6jebps17vp3n8i58h" => [ "kohar7mbb8dc2ce8a9qvl8hon4k53uhi", "" ],
    "kohar7mbb8dc2ce8a9qvl8hon4k53uhi" => [ "q04jkcevqvmu85r014c7dkba38o0ji5r", "A RRSIG" ],
    "q04jkcevqvmu85r014c7dkba38o0ji5r" => [ "r53bq7cc2uvmubfu5ocmm6pers9tk9en", "A RRSIG" ],
    "r53bq7cc2uvmubfu5ocmm6pers9tk9en" => [ "t644ebqk9bibcna874givr6joj62mlhv", "MX RRSIG" ],
    "t644ebqk9bibcna874givr6joj62mlhv" => [ "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "HINFO A AAAA RRSIG" ]
  }.freeze

  module_function

  def hash_of(name)
    HASHES.fetch(name)
  end

  def nsec3(owner_hash, flags: 1, iterations: ITERATIONS)
    next_hash, types = CHAIN.fetch(owner_hash)
    Dnsruby::RR.create(
      "#{owner_hash}.example. 3600 IN NSEC3 1 #{flags} #{iterations} #{SALT} #{next_hash} #{types}"
    )
  end

  def chain(*owner_hashes, flags: 1)
    owner_hashes = CHAIN.keys if owner_hashes.empty?
    owner_hashes.map { |owner| nsec3(owner, flags: flags) }
  end

  # A response carrying the given NSEC3 RRs (and any other authority
  # records) - the shape Nsec3Proof.verify and verify_nsecs consume.
  def response(qname, qtype, rcode: Dnsruby::RCode.NOERROR, authority: [], answer: [])
    msg = Dnsruby::Message.new(qname, qtype)
    msg.header.rcode = rcode
    answer.each { |rr| msg.add_answer(rr) }
    authority.each { |rr| msg.add_authority(rr) }
    msg
  end
end
