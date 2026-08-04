# The web composer's server side (EmailDraft).
#
# A draft is a message in the Drafts mailbox, so #edit reads one back out
# of its message and every save writes a new message and expunges the one
# it supersedes. #create therefore answers with the new id the client must
# send next time. A client holding a stale id is normal - a phone editing
# the same draft replaces it out from under us - and is handled by the
# model rather than treated as an error.
class DraftsController < ApplicationController
  before_action :set_message, only: %i[edit destroy]

  # Continue writing a saved draft.
  def edit
    @draft = EmailDraft.from_message(@message)
    @email_account = @message.mailbox.email_account
    @mailbox = @message.mailbox
  end

  def create
    draft = EmailDraft.new(draft_params)
    saved = draft.save

    if saved
      render json: { draft_message_id: saved.id, message_id: draft.message_id,
                     saved_at: saved.internal_date.iso8601 }
    elsif draft.errors.any?
      render json: { errors: draft.errors.full_messages }, status: :unprocessable_entity
    else
      # Nothing worth persisting yet (an empty composer on a timer). Not an
      # error - the client just has no draft id to carry forward.
      render json: { draft_message_id: nil }
    end
  end

  def destroy
    mailbox = @message.mailbox
    @message.destroy
    redirect_to email_account_mailbox_path(mailbox.email_account, mailbox),
                notice: "Draft discarded."
  end

  private

  # Only ever a draft. The id names an EmailMessage, so without this check
  # this route would delete any message in any mailbox.
  def set_message
    @message = EmailMessage.find(params[:id])
    raise ActiveRecord::RecordNotFound unless @message.draft?
  end

  def draft_params
    params.expect(draft: [ :email_account_id, :to, :cc, :subject, :body,
                           :in_reply_to, :references, :message_id, :draft_message_id ])
  end
end
