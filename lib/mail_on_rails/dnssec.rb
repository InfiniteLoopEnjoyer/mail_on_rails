# frozen_string_literal: true

# In-process DNSSEC validation, built on dnsruby (2.x).
#
# dnsruby is used as a library of parts, never as a resolver or a
# validator: its Message codec and record classes, the canonical RDATA
# encoding, the parsed DNSKEY public keys, DS digests and the NSEC3
# hash. Nothing here reopens a dnsruby class or calls into its
# SingleVerifier - that validator owns its own clock, work budget, trust
# store and network lookups, and this one brings all four.
#
# What lives under dnssec/:
#
#   Signature    one RRSIG over one RRset under one DNSKEY at a given
#                time (RSA, ECDSA, EdDSA; wildcard owners rebuilt from
#                the Labels field).
#   Nsec3Proof   the RFC 5155 section 8 denial proofs, Opt-Out aware.
#   NsecProof    the RFC 4035 NSEC proofs, same shape.
#   Transport    our own UDP/TCP client: CD + DO on every query.
#   Wire         what Transport reads off a reply before dnsruby does,
#                and the decode that survives a malformed TLSA record.
#   TrustAnchors the IANA root DS set.
#   Resolver     the validating stub forwarder that ties them together:
#                queries any upstream recursive with CD set, and computes
#                every verdict in process - RRSIG chains walked to the
#                root anchor, denials proven with NSEC/NSEC3 - so the
#                upstream needs no trust at all. Its Answer#status is the
#                RFC 4035 verdict DANE decisions hang on: :secure /
#                :insecure (Opt-Out spans, unsigned delegations -
#                "outside DNSSEC", never "securely absent") / :bogus
#                (defer, the moral equivalent of SERVFAIL).
#
# The outbound DANE path (SenderAuth::Dns#tlsa/#mx_answer) runs on
# this resolver; there is no external validating resolver anywhere in
# the deployment.
require "dnsruby"
require_relative "dnssec/signature"
require_relative "dnssec/nsec3_proof"
require_relative "dnssec/nsec_proof"
require_relative "dnssec/wire"
require_relative "dnssec/transport"
require_relative "dnssec/trust_anchors"
require_relative "dnssec/resolver"
