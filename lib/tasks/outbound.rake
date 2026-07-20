# Show the state of the outbound delivery queue.
#
#   bin/rails mail_on_rails:outbound            # counts + recent problem rows
#   bin/rails mail_on_rails:outbound LIMIT=20   # show more rows
namespace :mail_on_rails do
  desc "Show outbound mail queue status"
  task outbound: :environment do
    require "rainbow"

    counts = SmtpOutboundMessage.group(:status).count
    puts "Outbound queue: " + SmtpOutboundMessage.statuses.keys.map { |s|
      n = counts.fetch(s, 0)
      color = { "sent" => :green, "failed" => :red, "pending" => :yellow }.fetch(s, :white)
      "#{Rainbow(n.to_s).color(color)} #{s}"
    }.join(", ")

    limit = Integer(ENV.fetch("LIMIT", 10))
    problems = SmtpOutboundMessage.where.not(status: :sent).order(updated_at: :desc).limit(limit)
    problems.each do |m|
      puts "  ##{m.id} #{Rainbow(m.status).color(m.failed? ? :red : :yellow)}  " \
           "#{m.mail_from} -> #{m.recipient}  attempts=#{m.attempts} " \
           "next=#{m.next_attempt_at&.strftime("%H:%M:%S")}\n" \
           "      #{m.last_error&.byteslice(0, 200)}"
    end
  end
end
