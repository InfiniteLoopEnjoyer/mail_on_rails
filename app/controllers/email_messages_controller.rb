require "mail_on_rails/clamav_scanner"

class EmailMessagesController < ApplicationController
  before_action :set_email_message

  def show
    # Turbo prefetches links on hover; only an actual visit marks the message
    # read. A click served from the prefetch cache never re-requests, so the
    # page POSTs to mark_read instead (see the mark-read Stimulus controller).
    @email_message.mark_seen! unless prefetch_request?
    # Replying to your own unsent draft is nonsense; that page offers to
    # carry on writing it instead (see the view).
    @draft = EmailDraft.reply_to(@email_message, account: @email_account) unless @email_message.draft?
  end

  def mark_read
    @email_message.mark_seen!
    head :no_content
  end

  # Manual (re)scan from the message page: runs the stored bytes through
  # clamav and records the verdict, which is what unlocks (or keeps locked)
  # the attachment downloads. An unavailable scanner leaves the stored
  # verdict untouched - a clamd hiccup must not downgrade a real "clean".
  def rescan
    head :forbidden and return unless @email_message.rescannable?

    result = MailOnRails::ClamavScanner.scan(@email_message.raw)
    if result.unavailable?
      redirect_to message_path, alert: "The virus scanner is unavailable - try again shortly."
    else
      @email_message.update!(scan_status: result.infected? ? "infected" : "clean",
                             virus_name: result.virus)
      redirect_to message_path,
                  notice: result.infected? ? "Virus detected: #{result.virus}" : "No virus found."
    end
  end

  # "Mark as spam" / "Not spam" from the message page: an IMAP-style move
  # into Junk or back to INBOX. The moved message is a new row with a new
  # UID, so both land back on the folder the message left. Drafts are the
  # owner's own writing - nothing there to mark.
  def mark_spam
    head :forbidden and return if @email_message.draft? || @mailbox.junk?

    @email_message.move_to!(@email_account.junk_mailbox)
    redirect_to email_account_mailbox_path(@email_account, @mailbox), notice: "Moved to Junk."
  end

  def unmark_spam
    head :forbidden and return unless @mailbox.junk?

    @email_message.move_to!(@email_account.inbox)
    redirect_to email_account_mailbox_path(@email_account, @mailbox), notice: "Moved to INBOX."
  end

  # "Delete" from the message page: an IMAP-style move into Trash. Inside
  # Trash there is nowhere softer left to go, so the same action deletes
  # permanently (the view asks for confirmation there).
  def destroy
    if @mailbox.trash?
      @email_message.destroy!
      notice = "Message permanently deleted."
    else
      @email_message.move_to!(@email_account.trash_mailbox)
      notice = "Moved to Trash."
    end
    redirect_to email_account_mailbox_path(@email_account, @mailbox), notice: notice
  end

  # Serves one MIME attachment as a download. The view only links attachments
  # on messages that pass attachments_downloadable?; enforce the same rule
  # here so a pasted URL can't fetch an unscanned or infected payload.
  def attachment
    head :forbidden and return unless @email_message.attachments_downloadable?

    info = @email_message.attachments[params[:index].to_i]
    head :not_found and return unless info

    part = @email_message.parsed.attachments[info.index]
    send_data part.body.decoded,
              filename: info.filename, type: info.content_type, disposition: "attachment"
  end

  private

  def message_path
    email_account_mailbox_email_message_path(@email_account, @mailbox, @email_message)
  end

  def set_email_message
    @email_account = EmailAccount.find(params[:email_account_id])
    @mailbox = @email_account.mailboxes.find(params[:mailbox_id])
    @email_message = @mailbox.email_messages.find(params[:id])
  end

  def prefetch_request?
    [ request.headers["X-Sec-Purpose"], request.headers["Sec-Purpose"] ].any? { |h| h.to_s.include?("prefetch") }
  end
end
