# ban_covering for pages that render ban buttons (the auth attempts and
# live connection pages): the ban already covering an address or range
# shown on the page, if any - checked against the page's loaded @bans set,
# no per-row queries. Works for bare IPs and for whole ranges
# (IPAddr#include? only reports true when the ban covers the entire /24).
module BanCoverage
  extend ActiveSupport::Concern

  included do
    helper_method :ban_covering
  end

  private

  def ban_covering(target)
    addr = IPAddr.new(target.to_s)
    @bans.detect { |ban| ban.covers_addr?(addr) }
  rescue IPAddr::Error
    nil
  end
end
