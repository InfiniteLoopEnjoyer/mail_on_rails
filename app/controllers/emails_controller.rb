# Compose and send mail from the web UI. The From select is deliberately
# unscoped - any signed-in user (they are all admins here) can send as any
# hosted account. Routing/queueing lives in ComposedEmail#deliver.
class EmailsController < ApplicationController
  # Per-IP brake on scripted form posts; the per-ACCOUNT outbound cap is
  # ComposedEmail's send quota (shared with SMTP submission).
  rate_limit to: 30, within: 10.minutes, only: :create,
             with: -> { redirect_to new_email_path, alert: "Sending too quickly - try again later." }

  def new
    @draft = EmailDraft.new(email_account_id: params[:from] || EmailAccount.order(:email).first&.id)
    load_accounts
  end

  def create
    @composed_email = ComposedEmail.new(composed_email_params.except(:draft_message_id))
    if @composed_email.deliver
      discard_draft
      account = @composed_email.account
      sent = account.find_mailbox("Sent")
      destination = sent ? email_account_mailbox_path(account, sent) : email_account_path(account)
      redirect_to destination, notice: "Email sent."
    else
      # Re-render the composer with what was typed rather than an empty
      # form; the autosaved revision (if any) is still in Drafts and its id
      # goes back into the form so the next save keeps replacing it.
      # Attachments can't be re-rendered into a file input - the user
      # re-picks them - and EmailDraft has no such attribute anyway.
      @draft = EmailDraft.new(composed_email_params.except(:attachments))
      load_accounts
      render :new, status: :unprocessable_entity
    end
  end

  private

  # A sent reply must not leave its autosaved revision sitting in Drafts on
  # every device. Only after delivery commits, so a failed send keeps it.
  def discard_draft
    id = composed_email_params[:draft_message_id]
    return if id.blank?

    EmailDraft.new(email_account_id: @composed_email.email_account_id,
                   draft_message_id: id).discard
  end

  def load_accounts
    @email_accounts = EmailAccount.order(:email)
  end

  def composed_email_params
    params.expect(composed_email: [ :email_account_id, :to, :cc, :subject, :body,
                                    :in_reply_to, :references, :message_id, :draft_message_id,
                                    attachments: [] ])
  end
end
