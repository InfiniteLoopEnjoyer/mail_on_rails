# frozen_string_literal: true

module Dnsruby
  class SingleVerifier
    # The signature validity window is checked against Time.now deep
    # inside check_rr_data, which makes captured responses unverifiable
    # the moment their RRSIGs expire. verification_time pins the clock -
    # tests replay wire fixtures at their capture time, and callers with
    # their own clock (fake timers) stay consistent. nil keeps Time.now.
    attr_accessor :verification_time

    module TimeInjectableValidity
      def check_rr_data(rrset, sigrec)
        begin
          super
        rescue VerifyError => e
          # Swallow only the real-clock validity failure; every other
          # check (owner, class, type covered) still raises through.
          raise unless verification_time && e.message.include?("validity period")
        end
        return unless verification_time

        now = verification_time.to_i
        if sigrec.expiration < now || sigrec.inception > now
          raise VerifyError.new("Signature record not in validity period (at pinned verification time)")
        end
      end
    end
    prepend TimeInjectableValidity

    # Routes denial checking to the RFC 5155 proofs when a response
    # carries NSEC3 records. The stock verify_nsecs runs NSEC and NSEC3
    # RRsets through the same NSEC-shaped checks; hashed owner names can
    # never satisfy those, so every NSEC3 denial failed verification.
    # A zone signs with one scheme, so the presence of any NSEC3 record
    # selects the NSEC3 logic outright; pure-NSEC responses keep the
    # stock path.
    module Nsec3VerifyNsecs
      def verify_nsecs(msg)
        return super if Nsec3Proof.records(msg).empty?

        # Mirror the stock guard: a NOERROR answer for these qtypes
        # legitimately carries NSEC3 records without proving a denial.
        qtype = msg.question[0].qtype
        return if msg.rcode == RCode.NOERROR &&
                  (qtype == Types.ANY || qtype == Types.NSEC || qtype == Types.NSEC3)

        Nsec3Proof.verify(msg)
        nil
      end
    end

    prepend Nsec3VerifyNsecs
  end
end
