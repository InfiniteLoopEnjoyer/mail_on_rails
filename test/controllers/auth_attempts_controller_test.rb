require "test_helper"

class AuthAttemptsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
  end

  def log(username:, ip: "92.118.39.228", source: "smtp", outcome: "unknown_account", now: Time.current)
    AuthAttempt.record(ip: ip, username: username, source: source, outcome: outcome, now: now)
  end

  test "requires a signed-in user" do
    reset!
    get auth_attempts_path
    assert_redirected_to new_session_path
  end

  test "renders an empty state with no attempts" do
    get auth_attempts_path
    assert_response :success
    assert_select "h1", "Security"
  end

  test "shows source ranges and the dictionary" do
    %w[92.118.39.204 92.118.39.211].each { |ip| log(username: "cyrus", ip: ip) }
    log(username: "postgres", ip: "203.0.113.7")

    get auth_attempts_path
    assert_response :success
    assert_match "92.118.39.0/24", response.body
    assert_match "cyrus", response.body
    assert_match "postgres", response.body
  end

  # The whole point of the page: an attempt on an address that exists has
  # to be visually distinct from dictionary noise, not another table row.
  test "calls out attempts against real addresses" do
    log(username: "carol@example.com", outcome: "bad_credentials")

    get auth_attempts_path
    assert_response :success
    assert_select "h2", text: "Real addresses under attempt"
    assert_match "carol@example.com", response.body
  end

  test "omits the real-address callout when there is nothing to report" do
    log(username: "cyrus")

    get auth_attempts_path
    assert_select "h2", text: "Real addresses under attempt", count: 0
  end

  test "the window selector narrows the data" do
    log(username: "old-attempt@example.test", now: 10.days.ago)
    log(username: "new-attempt@example.test", now: 1.hour.ago)

    get auth_attempts_path(window: "24h")
    assert_match "new-attempt@example.test", response.body
    assert_no_match(/old-attempt@example.test/, response.body)

    get auth_attempts_path(window: "30d")
    assert_match "old-attempt@example.test", response.body
  end

  test "an unknown window falls back to the default rather than erroring" do
    get auth_attempts_path(window: "../../etc")
    assert_response :success
  end

  test "range links from the index lead to the drill-down" do
    log(username: "cyrus", ip: "92.118.39.204")

    get auth_attempts_path
    assert_select "a[href=?]", range_auth_attempts_path(cidr: "92.118.39.0/24", window: "7d"),
                  text: "92.118.39.0/24"
  end

  test "the range drill-down lists each address with its totals" do
    2.times { log(username: "cyrus", ip: "92.118.39.204") }
    log(username: "postgres", ip: "92.118.39.211", source: "imap")
    log(username: "outside", ip: "203.0.113.7")

    get range_auth_attempts_path(cidr: "92.118.39.0/24")
    assert_response :success
    assert_match "92.118.39.204", response.body
    assert_match "92.118.39.211", response.body
    assert_no_match(/203\.0\.113\.7/, response.body)
  end

  test "a malformed range bounces back to the index" do
    get range_auth_attempts_path(cidr: "../../etc")
    assert_redirected_to auth_attempts_path(window: "7d")
  end

  test "banned rows show a badge instead of another ban button" do
    log(username: "cyrus", ip: "92.118.39.204")
    BannedIp.create!(cidr: "92.118.39.0/24")

    get range_auth_attempts_path(cidr: "92.118.39.0/24")
    assert_match "banned", response.body
  end

  test "the index manages manual bans and summarizes DROP imports" do
    BannedIp.create!(cidr: "203.0.113.0/24", note: "spray campaign")
    BannedIp.create!(cidr: "198.51.100.0/24", source: "spamhaus_drop")

    get auth_attempts_path
    assert_select "h2", text: "Banned IPs"
    assert_match "203.0.113.0/24", response.body
    assert_match "spray campaign", response.body
    assert_match "1 range from the Spamhaus DROP list", response.body
    assert_no_match(/198\.51\.100\.0/, response.body)
  end

  # Collapsed noise is counted but not listed, so the page has to say so -
  # a total that silently excludes rows reads as "this is everything".
  test "discloses collapsed rows when any exist" do
    previous = ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"]
    ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"] = "2"
    5.times { log(username: "cyrus") }

    get auth_attempts_path
    assert_match "not listed individually", response.body
  ensure
    previous ? ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"] = previous
             : ENV.delete("MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP")
  end
end
