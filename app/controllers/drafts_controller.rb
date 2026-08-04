# Autosave endpoint for the web composer (EmailDraft).
#
# Every save writes a new message into Drafts and expunges the revision it
# supersedes, so the response carries the new id the client must send with
# its next save. A client holding a stale id is normal - a phone editing
# the same draft replaces it out from under us - and is handled by the
# model rather than treated as an error.
class DraftsController < ApplicationController
  def create
    draft = build_draft
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
    draft = build_draft
    draft.draft_message_id = params[:id]
    draft.discard
    head :no_content
  end

  private

  def build_draft
    EmailDraft.new(draft_params)
  end

  def draft_params
    params.expect(draft: [ :email_account_id, :to, :cc, :subject, :body,
                           :in_reply_to, :references, :message_id, :draft_message_id ])
  end
end
