# frozen_string_literal: true

# In-process DNSSEC validation, built on dnsruby.
#
# dnsruby (1.74.0) verifies RRSIG chains (Dnsruby::Dnssec/SingleVerifier)
# and proves denial of existence with NSEC - but its NSEC3 (RFC 5155)
# support stops at the record codec: NSEC3#check_name_in_range is a stub
# returning false, and SingleVerifier#verify_nsecs pushes NSEC3 RRsets
# through NSEC logic that can never match a hashed owner name. The net
# effect is that any denial from an NSEC3 zone (com, net, org, most
# TLDs) fails verification outright.
#
# The files under dnssec/ patch that gap in place: hashed-range matching
# on the NSEC3 record itself, the RFC 5155 section 8 proofs as a
# standalone module (Dnsruby::Nsec3Proof), and a verify_nsecs override
# that dispatches NSEC3 responses to those proofs. The patches are
# written in dnsruby's idiom and namespaced inside Dnsruby so they can be
# offered upstream; until then they load from here.
#
# On top of the patches sits MailOnRails::Dnssec::Resolver, a validating
# stub forwarder: our own transport queries any upstream recursive with
# CD set, and every verdict - RRSIG chains walked to the IANA root trust
# anchor, denials proven with NSEC/NSEC3 - is computed in process, so the
# upstream needs no trust at all. Its Answer#status is the RFC 4035
# four-state verdict DANE decisions hang on: :secure / :insecure (Opt-Out
# spans, unsigned delegations - "outside DNSSEC", never "securely
# absent") / :bogus (defer, the moral equivalent of SERVFAIL).
#
# The outbound DANE path (SenderAuth::Dns#tlsa/#mx_answer) runs on
# this resolver; there is no external validating resolver anywhere in
# the deployment.
require "dnsruby"
require_relative "dnssec/nsec3_patch"
require_relative "dnssec/nsec3_proof"
require_relative "dnssec/nsec_proof"
require_relative "dnssec/eddsa_patch"
require_relative "dnssec/single_verifier_patch"
require_relative "dnssec/transport"
require_relative "dnssec/trust_anchors"
require_relative "dnssec/resolver"
