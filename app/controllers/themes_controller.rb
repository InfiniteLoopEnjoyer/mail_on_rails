# The profile's Appearance card PATCHes here (theme Stimulus controller) as
# the user clicks; each click sends just the attribute it changed. Always
# your own preference - there is no admin editing of somebody else's theme.
class ThemesController < ApplicationController
  def update
    if Current.user.update(params.permit(:appearance, :accent))
      head :no_content
    else
      head :unprocessable_entity
    end
  end
end
