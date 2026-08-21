# frozen_string_literal: true

require "test_helper"
require "active_job"

# Domain's create hook enqueues a DNS-check refresh; the db harness loads
# no jobs, so pull the class in and use the test adapter (no real queue).
# The job takes the domain record itself, which Active Job serializes via
# GlobalID - included into Active Record by a railtie in a real app, by
# hand here.
require File.expand_path("../../app/jobs/mail_on_rails/base_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/dns_check_refresh_job", __dir__)
require File.expand_path("../../app/jobs/mail_on_rails/ingest_fbl_report_job", __dir__)
require "global_id"
GlobalID.app ||= "mail-on-rails-db-suite"
ActiveRecord::Base.include(GlobalID::Identification)

# The operational addresses every hosted domain must answer: creating a
# domain mints a postmaster@ account (RFC 5321 s4.5.1) with abuse@
# (RFC 2142) and mailer-daemon@ (the From: on our DSN bounces) as aliases
# into the same INBOX, alongside the dmarc@ and
# tls-rpt@ report accounts. ensure_postmaster_account! is also the
# backfill migration's worker, so it must be idempotent and defer to any
# arrangement the operator already made for these addresses.
class DomainTest < DbSuite::TestCase
  def setup
    super
    ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
    ActiveJob::Base.queue_adapter = :test
  end

  test "creating a domain auto-creates the postmaster account with abuse and mailer-daemon aliases" do
    MailOnRails::Domain.create!(name: "example.test")

    postmaster = MailOnRails::EmailAccount.find_by(email: "postmaster@example.test")
    assert postmaster, "postmaster account must be auto-created"
    abuse = MailOnRails::EmailAlias.find_by(email: "abuse@example.test")
    assert abuse, "abuse alias must be auto-created"
    assert_equal postmaster, abuse.email_account
    mailer_daemon = MailOnRails::EmailAlias.find_by(email: "mailer-daemon@example.test")
    assert mailer_daemon, "mailer-daemon alias must be auto-created"
    assert_equal postmaster, mailer_daemon.email_account
  end

  test "ensure_postmaster_account! is idempotent" do
    domain = MailOnRails::Domain.create!(name: "example.test")
    postmaster = MailOnRails::EmailAccount.find_by!(email: "postmaster@example.test")

    assert_equal postmaster, domain.ensure_postmaster_account!
    assert_equal 1, MailOnRails::EmailAccount.where(email: "postmaster@example.test").count
    assert_equal 1, MailOnRails::EmailAlias.where(email: "abuse@example.test").count
    assert_equal 1, MailOnRails::EmailAlias.where(email: "mailer-daemon@example.test").count
    assert_equal 1, MailOnRails::EmailAlias.where(email: "postmaster@mail.example.test").count
  end

  # The backfill case: a domain from before mailer-daemon support already
  # has its postmaster account and abuse alias; rerunning the ensure adds
  # only the missing alias.
  test "ensure_postmaster_account! backfills a missing mailer-daemon alias" do
    domain = MailOnRails::Domain.create!(name: "example.test")
    MailOnRails::EmailAlias.find_by!(email: "mailer-daemon@example.test").destroy!

    domain.ensure_postmaster_account!
    assert_equal MailOnRails::EmailAccount.find_by!(email: "postmaster@example.test"),
                 MailOnRails::EmailAlias.find_by!(email: "mailer-daemon@example.test").email_account
  end

  test "creating a domain auto-creates the operational aliases at its mail-host name" do
    MailOnRails::Domain.create!(name: "example.test")

    postmaster = MailOnRails::EmailAccount.find_by!(email: "postmaster@example.test")
    %w[postmaster abuse mailer-daemon].each do |local|
      host_alias = MailOnRails::EmailAlias.find_by(email: "#{local}@mail.example.test")
      assert host_alias, "#{local}@mail.example.test alias must be auto-created"
      assert_equal postmaster, host_alias.email_account
    end
  end

  # Hosting the mail-host name itself as a domain after its parent: the
  # parent's creation already minted postmaster@mail.<parent> as an alias,
  # so the new domain's ensure must hang off that alias's account instead
  # of colliding with it (EmailAccount refuses addresses taken by aliases).
  test "hosting a domain's mail-host name reuses the existing postmaster alias arrangement" do
    MailOnRails::Domain.create!(name: "example.test")
    postmaster = MailOnRails::EmailAccount.find_by!(email: "postmaster@example.test")

    domain = MailOnRails::Domain.create!(name: "mail.example.test")

    assert_equal postmaster, domain.ensure_postmaster_account!
    assert_not MailOnRails::EmailAccount.exists?(email: "postmaster@mail.example.test"),
               "the existing alias must not be shadowed by a new account"
    assert_equal postmaster,
                 MailOnRails::EmailAlias.find_by!(email: "abuse@mail.mail.example.test").email_account
  end

  test "a pre-existing mailer-daemon arrangement is left alone" do
    other = MailOnRails::EmailAccount.create!(email: "ops@example.test", name: "Ops",
                                              password: MailOnRails::EmailAccount.generate_password)
    MailOnRails::EmailAlias.create!(email: "mailer-daemon@example.test", email_account: other)
    MailOnRails::Domain.create!(name: "example.test")

    assert_equal other, MailOnRails::EmailAlias.find_by!(email: "mailer-daemon@example.test").email_account
  end

  test "a pre-existing abuse account is left alone" do
    abuse = MailOnRails::EmailAccount.create!(email: "abuse@example.test", name: "Abuse desk",
                                              password: MailOnRails::EmailAccount.generate_password)
    MailOnRails::Domain.create!(name: "example.test")

    assert MailOnRails::EmailAccount.exists?(email: "postmaster@example.test")
    assert_not MailOnRails::EmailAlias.exists?(email: "abuse@example.test"),
               "the operator's abuse account must not be shadowed by an alias"
    assert abuse.reload.persisted?
  end

  test "a pre-existing abuse alias on another account is left alone" do
    other = MailOnRails::EmailAccount.create!(email: "ops@example.test", name: "Ops",
                                              password: MailOnRails::EmailAccount.generate_password)
    MailOnRails::EmailAlias.create!(email: "abuse@example.test", email_account: other)
    MailOnRails::Domain.create!(name: "example.test")

    assert_equal other, MailOnRails::EmailAlias.find_by!(email: "abuse@example.test").email_account
  end

  test "creating a domain auto-creates the fbl account and jmrp alias" do
    MailOnRails::Domain.create!(name: "example.test")

    fbl = MailOnRails::EmailAccount.find_by(email: "fbl@example.test")
    assert fbl, "fbl account must be auto-created"
    jmrp = MailOnRails::EmailAlias.find_by(email: "jmrp@example.test")
    assert jmrp, "jmrp alias must be auto-created"
    assert_equal fbl, jmrp.email_account
  end

  test "ensure_fbl_account! is idempotent" do
    domain = MailOnRails::Domain.create!(name: "example.test")
    fbl = MailOnRails::EmailAccount.find_by!(email: "fbl@example.test")

    assert_equal fbl, domain.ensure_fbl_account!
    assert_equal 1, MailOnRails::EmailAccount.where(email: "fbl@example.test").count
    assert_equal 1, MailOnRails::EmailAlias.where(email: "jmrp@example.test").count
  end

  test "a pre-existing jmrp account is left alone" do
    jmrp = MailOnRails::EmailAccount.create!(email: "jmrp@example.test", name: "JMRP desk",
                                             password: MailOnRails::EmailAccount.generate_password)
    MailOnRails::Domain.create!(name: "example.test")

    assert MailOnRails::EmailAccount.exists?(email: "fbl@example.test")
    assert_not MailOnRails::EmailAlias.exists?(email: "jmrp@example.test"),
               "the operator's jmrp account must not be shadowed by an alias"
    assert jmrp.reload.persisted?
  end

  test "fbl account address routes to the FBL ingestion job" do
    domain = MailOnRails::Domain.create!(name: "example.test")

    assert_equal MailOnRails::IngestFblReportJob, MailOnRails::Domain.ingestion_job_for(domain.fbl_address)
    assert_nil MailOnRails::Domain.ingestion_job_for("fbl@unhosted.test")
  end
end
