# frozen_string_literal: true

# A miniature DNSSEC signing authority for resolver tests: generates real
# keys (RSA-SHA256, ECDSA P-256, Ed25519), publishes them as DNSKEY/DS
# records, and signs RRsets with genuine signatures - so the resolver
# tests exercise the same cryptography as production, just under a test
# trust anchor. Signing mirrors verify_rrset's canonical construction
# (RFC 4034 section 3.1.8.1).
class TestZone
  ALG_RSASHA256 = 8
  ALG_ECDSAP256 = 13
  ALG_ED25519 = 15

  attr_reader :name, :algorithm, :dnskey

  def initialize(name, algorithm: ALG_RSASHA256)
    @name = name
    @algorithm = algorithm
    @pkey = generate_key
    @dnskey = build_dnskey
  end

  def dnskey_rrset(signed_at:, expires_at:)
    rrset = Dnsruby::RRSet.new(@dnskey)
    sign(rrset, signed_at: signed_at, expires_at: expires_at)
  end

  def ds(digest_type = 2)
    scaffold = Dnsruby::RR.create("#{@name} 3600 IN DS 0 8 #{digest_type} 00")
    digest = scaffold.digest_key(@dnskey)
    Dnsruby::RR.create("#{@name} 3600 IN DS #{@dnskey.key_tag} #{@algorithm} #{digest_type} #{digest.unpack1("H*")}")
  end

  # Signs +rrset+ in place and returns it. +sign_as+ is the owner the
  # signature is computed over - pass the "*.parent" form when the
  # response carries a wildcard-expanded owner. +labels+ overrides the
  # RRSIG Labels field the same way.
  def sign(rrset, signed_at:, expires_at:, sign_as: nil, labels: nil)
    owner = rrset.name.to_s(true)
    sign_owner = sign_as || owner
    labels ||= Dnsruby::Name.create(sign_owner).labels.reject { |l| l.to_s == "*" }.length

    rrsig = Dnsruby::RR.create(
      "#{owner} #{rrset.ttl} IN RRSIG #{rrset.type.string} #{@algorithm} #{labels} #{rrset.ttl} " \
      "#{fmt_time(expires_at)} #{fmt_time(signed_at)} #{@dnskey.key_tag} #{@name} AA=="
    )
    rrsig.signature = raw_signature(sig_data_for(rrset, rrsig, sign_owner))
    rrset.add(rrsig)
    rrset
  end

  def self.rrset(*rrs)
    Dnsruby::RRSet.new(rrs.flatten)
  end

  private

  def generate_key
    case @algorithm
    when ALG_RSASHA256 then OpenSSL::PKey::RSA.new(2048)
    when ALG_ECDSAP256 then OpenSSL::PKey::EC.generate("prime256v1")
    when ALG_ED25519 then OpenSSL::PKey.generate_key("ED25519")
    else raise ArgumentError, "unsupported test algorithm #{@algorithm}"
    end
  end

  # RFC 4034 section 2 wire form of the public key, per algorithm family.
  def key_blob
    case @algorithm
    when ALG_RSASHA256
      exponent = @pkey.e.to_s(2)
      [ exponent.bytesize ].pack("C") + exponent + @pkey.n.to_s(2)
    when ALG_ECDSAP256
      @pkey.public_key.to_octet_string(:uncompressed).byteslice(1..) # x || y, sans 0x04
    when ALG_ED25519
      @pkey.raw_public_key
    end
  end

  def build_dnskey
    Dnsruby::RR.create("#{@name} 3600 IN DNSKEY 257 3 #{@algorithm} #{[ key_blob ].pack("m0")}")
  end

  def sig_data_for(rrset, rrsig, sign_owner)
    data = rrsig.sig_data
    rrset.sort_canonical.rrs.each do |rr|
      copy = rr.clone
      copy.name = Dnsruby::Name.create(sign_owner)
      copy.ttl = rrsig.original_ttl
      data += Dnsruby::MessageEncoder.new { |msg| msg.put_rr(copy, true) }.to_s.force_encoding(Encoding::BINARY)
    end
    data
  end

  def raw_signature(data)
    case @algorithm
    when ALG_RSASHA256
      @pkey.sign(OpenSSL::Digest::SHA256.new, data)
    when ALG_ECDSAP256
      der = @pkey.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(data))
      OpenSSL::ASN1.decode(der).value.map { |int| int.value.to_s(2).rjust(32, "\x00") }.join
    when ALG_ED25519
      @pkey.sign(nil, data)
    end
  end

  def fmt_time(time)
    time.utc.strftime("%Y%m%d%H%M%S")
  end
end

# Canned upstream for Resolver tests: serves prepared Dnsruby::Messages
# keyed by "qname|QTYPE" and records every query for cache assertions.
# Responses round-trip through the wire codec so tests also cover
# encode/decode of everything they build.
class FakeTransport
  attr_reader :queries

  def initialize(responses = {})
    @responses = responses
    @queries = []
  end

  def add(msg)
    q = msg.question[0]
    @responses["#{q.qname.to_s(true).downcase}|#{q.qtype}"] = msg
    self
  end

  def query(name, type)
    key = "#{name.to_s.downcase}|#{Dnsruby::Types.new(type)}"
    @queries << key
    msg = @responses[key]
    raise MailOnRails::Dnssec::Transport::TempError, "no fixture for #{key}" unless msg

    Dnsruby::Message.decode(msg.encode)
  end
end

# Response assembly shorthand.
module DnsResponse
  module_function

  def build(qname, qtype, rcode: Dnsruby::RCode.NOERROR, answer: [], authority: [])
    msg = Dnsruby::Message.new(qname, qtype)
    msg.header.rcode = rcode
    msg.header.qr = true
    answer.each { |rrset| add_rrset(msg, rrset, :answer) }
    authority.each { |rrset| add_rrset(msg, rrset, :authority) }
    msg
  end

  def add_rrset(msg, rrset, section)
    rrs = rrset.is_a?(Dnsruby::RRSet) ? rrset.rrs + rrset.sigs : [ rrset ]
    rrs.each { |rr| section == :answer ? msg.add_answer(rr) : msg.add_authority(rr) }
  end
end
