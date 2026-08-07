class MailboxesController < ApplicationController
  before_action :set_email_account
  before_action :set_mailbox, only: %i[show edit update destroy export]
  rate_limit to: 30, within: 10.minutes, only: %i[create update destroy],
             with: -> { redirect_to email_account_path(params[:email_account_id]), alert: "Try again later." }

  # Newest-first, one page at a time - a mailbox can hold years of mail and
  # rendering it all in one response hurts long before the query does
  # (there's an index on mailbox_id + internal_date).
  MESSAGES_PER_PAGE = 50

  # One list row per conversation: the messages sharing a thread_id,
  # oldest first (the row shows the newest and a count).
  MailboxThread = Struct.new(:messages) do
    def latest = messages.last
    def count = messages.size
    def unseen? = messages.any? { |m| !m.seen? }
  end

  def show
    scope = @mailbox.email_messages
    @message_count = scope.count
    # Threads paginate by latest activity: the thread with the newest
    # message comes first, however old its roots are.
    @thread_count = scope.distinct.count(:thread_id)
    @pages = [ @thread_count.fdiv(MESSAGES_PER_PAGE).ceil, 1 ].max
    @page = params[:page].to_i.clamp(1, @pages)
    page_threads = scope.group(:thread_id)
                        .select("thread_id, MAX(internal_date) AS latest_date, MAX(uid) AS latest_uid")
                        .order("latest_date DESC, latest_uid DESC")
                        .offset((@page - 1) * MESSAGES_PER_PAGE).limit(MESSAGES_PER_PAGE)
    grouped = scope.where(thread_id: page_threads.map(&:thread_id))
                   .order(:internal_date, :uid).group_by(&:thread_id)
    @threads = page_threads.filter_map { |t| (messages = grouped[t.thread_id]) && MailboxThread.new(messages) }
  end

  # The whole folder as one standard mbox download. The export enumerates
  # lazily (one message in memory at a time) and Rack streams the
  # enumerator, so a folder holding years of mail never builds a
  # folder-sized string.
  def export
    export = MboxExport.new(@mailbox)
    headers["Content-Disposition"] = "attachment; filename=\"#{export.filename}\""
    headers["Last-Modified"] = Time.current.httpdate # disable Rack::ETag buffering
    self.response_body = export.each
    response.content_type = "application/mbox"
  end

  def new
    @mailbox = @email_account.mailboxes.new
  end

  def create
    @mailbox = @email_account.mailboxes.new(mailbox_params)
    if @mailbox.save
      redirect_to email_account_path(@email_account), notice: "Folder #{@mailbox.name} created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    if @mailbox.update(mailbox_params)
      redirect_to email_account_mailbox_path(@email_account, @mailbox), notice: "Folder updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    if @mailbox.destroy
      redirect_to email_account_path(@email_account), notice: "Folder #{@mailbox.name} deleted.", status: :see_other
    else
      redirect_to email_account_mailbox_path(@email_account, @mailbox),
                  alert: @mailbox.errors.full_messages.to_sentence, status: :see_other
    end
  end

  private

  def set_email_account
    @email_account = EmailAccount.find(params[:email_account_id])
  end

  def set_mailbox
    @mailbox = @email_account.mailboxes.find(params[:id])
  end

  def mailbox_params
    params.expect(mailbox: [ :name ])
  end
end
