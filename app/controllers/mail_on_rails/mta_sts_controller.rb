# Serves the MTA-STS policy file sending MTAs fetch from
# https://mta-sts.<domain>/.well-known/mta-sts.txt. The policy is the
# same for every hosted domain (see MtaSts), so no per-host branching:
# any Host that reaches this app gets the one policy.
module MailOnRails
  # Deliberately ActionController::Base, not the host's ApplicationController:
  # sending MTAs fetch this anonymously, so no host auth concern may apply.
  class MtaStsController < ActionController::Base
    # No state-changing actions (GET-only), but Base skips the host app's
    # default forgery protection - restore it rather than reason about it.
    protect_from_forgery with: :exception

    def show
      return head :not_found unless MtaSts.configured?

      render plain: MtaSts.policy
    end
  end
end
