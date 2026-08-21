# frozen_string_literal: true

require "puma/plugin"

module MailOnRails
  # Settings for the dev clamd container managed by the clamav_dev Puma
  # plugin below.
  module ClamavDev
    CONTAINER = "clamav-dev"
    IMAGE = "clamav/clamav:1.4" # keep in step with the clamav accessory in config/deploy.yml
    VOLUME = "clamav-db"        # persists signatures across container restarts
    ADDR = "127.0.0.1:3310"
    HEALTHY_DEADLINE = 15 * 60  # seconds; first boot downloads ~300MB of signatures
  end
end

# Development-only (registered from config/puma.rb): keeps a local clamd
# docker container running for MailOnRails::ClamavScanner. Scanning is off
# until SMTP_CLAMAV_ADDR is set (deploys point it at the clamav Kamal
# accessory), so this plugin points it at a local container it manages, or
# pins it to "" (scanning off, mail delivered unscanned) when docker is
# unavailable.
# An explicit SMTP_CLAMAV_ADDR in the environment (including "") wins - the
# plugin then touches nothing.
#
# The container is left running on Puma shutdown: clamd cold starts take
# minutes and dev restarts are frequent. `docker stop clamav-dev` frees the
# ~1.5GB it holds; the clamav-db volume keeps later starts fast.
Puma::Plugin.create do
  def start(launcher)
    @log = launcher.log_writer
    return if ENV.key?("SMTP_CLAMAV_ADDR")

    # The address must be settled synchronously here: the Solid Queue
    # supervisor forks its worker processes at after_booted, the mailroom
    # scan runs inside those workers, and an ENV change made later (say,
    # once clamd turns healthy) never reaches an already-forked process.
    # So with docker present the env points at the container immediately;
    # until clamd is healthy, scans come back :unavailable and inbound dev
    # mail is quarantined "unscanned" (only a first-ever boot takes long).
    unless docker?
      ENV["SMTP_CLAMAV_ADDR"] = ""
      log "docker unavailable - dev virus scanning off " \
          "(start docker, or set SMTP_CLAMAV_ADDR to an external clamd)"
      return
    end

    ENV["SMTP_CLAMAV_ADDR"] = MailOnRails::ClamavDev::ADDR
    in_background do
      if ensure_container && wait_healthy
        log "clamd healthy - scanning live at #{MailOnRails::ClamavDev::ADDR}"
      else
        log "#{MailOnRails::ClamavDev::CONTAINER} did not start or never turned healthy - " \
            "scans stay unavailable, inbound mail quarantines as \"unscanned\" " \
            "(docker logs #{MailOnRails::ClamavDev::CONTAINER})"
      end
    end
  end

  private

  def log(message)
    @log.log "clamav_dev: #{message}"
  end

  # A reachable docker daemon reports a bare version string. Exit status
  # alone is not enough: the Docker Desktop WSL shim prints its "activate
  # WSL integration" notice and still exits 0.
  def docker?
    version = `docker info --format '{{.ServerVersion}}' 2>/dev/null`.strip
    $?.success? && !version.empty? && !version.include?(" ")
  end

  def ensure_container
    case container_state
    when "running"
      true
    when ""
      log "starting #{MailOnRails::ClamavDev::IMAGE} as #{MailOnRails::ClamavDev::CONTAINER} " \
          "(a first boot downloads ~300MB of signatures and takes minutes to turn healthy)"
      system("docker", "run", "-d", "--name", MailOnRails::ClamavDev::CONTAINER,
             "-p", "3310:3310", "-v", "#{MailOnRails::ClamavDev::VOLUME}:/var/lib/clamav",
             MailOnRails::ClamavDev::IMAGE, out: File::NULL)
    else
      system("docker", "start", MailOnRails::ClamavDev::CONTAINER, out: File::NULL)
    end
  end

  def container_state
    `docker inspect -f '{{.State.Status}}' #{MailOnRails::ClamavDev::CONTAINER} 2>/dev/null`.strip
  end

  # The image ships its own HEALTHCHECK (clamdcheck). Bail early only when
  # the container itself stops; a long "starting"/"unhealthy" stretch is
  # normal while a first boot downloads signatures.
  def wait_healthy
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + MailOnRails::ClamavDev::HEALTHY_DEADLINE
    while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      return false unless container_state == "running"
      health = `docker inspect -f '{{.State.Health.Status}}' #{MailOnRails::ClamavDev::CONTAINER} 2>/dev/null`.strip
      return true if health == "healthy"

      sleep 5
    end
    false
  end
end
