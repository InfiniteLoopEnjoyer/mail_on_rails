require "test_helper"

class SettingTest < ActiveSupport::TestCase
  test "trash retention defaults to 30 days with no row" do
    assert_empty Setting.where(key: "trash_retention_days")
    assert_equal 30, Setting.trash_retention_days
  end

  test "trash retention round-trips and updates in place" do
    Setting.trash_retention_days = 7
    assert_equal 7, Setting.trash_retention_days

    Setting.trash_retention_days = "14"
    assert_equal 14, Setting.trash_retention_days
    assert_equal 1, Setting.where(key: "trash_retention_days").count
  end

  test "trash retention rejects junk and non-positive values" do
    assert_raises(ArgumentError) { Setting.trash_retention_days = "soon" }
    assert_raises(ArgumentError) { Setting.trash_retention_days = 0 }
    assert_raises(ArgumentError) { Setting.trash_retention_days = -3 }
    assert_raises(TypeError) { Setting.trash_retention_days = nil }
    assert_equal 30, Setting.trash_retention_days
  end
end
