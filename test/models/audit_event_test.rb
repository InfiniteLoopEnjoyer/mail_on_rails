require "test_helper"

# The audit trail's row semantics: immutable once written, legible after
# both the actor and the subject are gone.
class AuditEventTest < ActiveSupport::TestCase
  setup do
    @user = users(:one)
  end

  test "record! snapshots the actor's email and a subject label" do
    account = EmailAccount.create!(email: "audited@example.com", password: "secret123")
    event = AuditEvent.record!(user: @user, action: "email_account.create",
                               subject: account, ip: "203.0.113.9", details: { note: "x", empty: "" })

    assert_equal @user.email_address, event.user_email
    assert_equal account, event.subject
    assert_equal "audited@example.com", event.subject_label
    assert_equal({ "note" => "x" }, event.details, "blank detail values are dropped")
    assert_equal "203.0.113.9", event.ip
  end

  test "rows survive deleting the subject and the actor" do
    account = EmailAccount.create!(email: "gone@example.com", password: "secret123")
    event = AuditEvent.record!(user: @user, action: "email_account.destroy", subject: account)

    account.destroy!
    actor = User.create!(email_address: "leaving@example.com", password: "secret123456")
    other = AuditEvent.record!(user: actor, action: "user.create", subject: actor)
    actor.destroy!

    assert_equal "gone@example.com", event.reload.subject_label
    assert_nil event.reload.subject
    assert_nil other.reload.user, "the FK must nullify, not cascade"
    assert_equal "leaving@example.com", other.user_email
  end

  test "rows are immutable" do
    event = AuditEvent.record!(user: @user, action: "settings.update")

    assert_raises(ActiveRecord::ReadOnlyRecord) { event.update!(action: "rewritten") }
    assert_raises(ActiveRecord::ReadOnlyRecord) { event.destroy! }
    assert_equal "settings.update", event.reload.action
  end

  test "label_for falls back through common attributes to class and id" do
    ban = BannedIp.create!(cidr: "203.0.113.0/24")
    assert_equal "203.0.113.0/24", AuditEvent.label_for(ban)

    message = EmailMessage.new(id: 7)
    assert_equal "EmailMessage #7", AuditEvent.label_for(message)
    assert_nil AuditEvent.label_for(nil)
  end
end
