require "test_helper"

# The audit viewer and the write hooks on the admin surfaces: mutating an
# admin resource leaves a row that /audit renders.
class AuditTrailTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
  end

  test "admin mutations leave audit rows with actor, subject, and ip" do
    post email_accounts_url, params: { email_account: { email: "new@example.com" } }
    account = EmailAccount.find_by!(email: "new@example.com")

    event = AuditEvent.sole
    assert_equal "email_account.create", event.action
    assert_equal users(:one).email_address, event.user_email
    assert_equal account, event.subject
    assert_equal "new@example.com", event.subject_label
    assert event.ip.present?

    patch email_account_url(account), params: { email_account: { email: "new@example.com", name: "Renamed" } }
    assert_equal "email_account.update", AuditEvent.newest_first.first.action
    assert_includes AuditEvent.newest_first.first.details["changes"], "name"

    delete email_account_url(account)
    assert_equal "email_account.destroy", AuditEvent.newest_first.first.action
    assert_equal "new@example.com", AuditEvent.newest_first.first.subject_label
  end

  test "user and settings mutations are audited" do
    post users_url, params: { user: { email_address: "second@example.com" } }
    assert_equal "user.create", AuditEvent.newest_first.first.action

    patch settings_url, params: { trash_retention_days: "14" }
    event = AuditEvent.newest_first.first
    assert_equal "settings.update", event.action
    assert_equal 14, event.details["trash_retention_days"]
    assert_nil event.subject
  end

  test "the viewer lists events newest first and requires a session" do
    AuditEvent.record!(user: users(:one), action: "settings.update", details: { first: "1" })
    AuditEvent.record!(user: users(:one), action: "user.create", details: { second: "2" })

    get audit_events_url
    assert_response :success
    body = response.body
    assert_operator body.index("user.create"), :<, body.index("settings.update"),
                    "newest event must render first"

    sign_out
    get audit_events_url
    assert_redirected_to new_session_url
  end

  test "the viewer paginates" do
    60.times { |i| AuditEvent.record!(user: users(:one), action: "settings.update", details: { i: i }) }

    get audit_events_url
    assert_response :success
    assert_select "tbody tr", 50
    assert_match(/Page 1 of 2 \(60 events\)/, response.body)

    get audit_events_url(page: 2)
    assert_select "tbody tr", 10
  end
end
