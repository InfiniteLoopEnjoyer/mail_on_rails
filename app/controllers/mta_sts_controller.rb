# Serves the MTA-STS policy file sending MTAs fetch from
# https://mta-sts.<domain>/.well-known/mta-sts.txt. The policy is the
# same for every hosted domain (see MtaSts), so no per-host branching:
# any Host that reaches this app gets the one policy.
class MtaStsController < ApplicationController
  allow_unauthenticated_access

  def show
    return head :not_found unless MtaSts.configured?

    render plain: MtaSts.policy
  end
end
