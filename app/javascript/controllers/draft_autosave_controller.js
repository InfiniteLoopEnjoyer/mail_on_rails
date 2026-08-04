import { Controller } from "@hotwired/stimulus"
import { post } from "@rails/request.js"

// Debounced autosave for the composer.
//
// Each save writes a new message into the Drafts mailbox and expunges the
// one it supersedes, so the server hands back a new id every time and we
// carry it into the next save. Saves are debounced and skipped when nothing
// the user typed has changed: every save is a real message write plus an
// expunge tombstone, and saving per keystroke would churn the mailbox that
// every other device is syncing.
export default class extends Controller {
  static targets = ["field", "draftId", "messageId", "status"]
  static values = { url: String, delay: { type: Number, default: 3000 } }

  connect() {
    this.lastSaved = this.snapshot()
    this.timer = null
    // A draft still in the debounce window when the tab is hidden or closed
    // would otherwise be lost.
    this.flush = this.flush.bind(this)
    document.addEventListener("visibilitychange", this.flush)
    window.addEventListener("pagehide", this.flush)
  }

  disconnect() {
    clearTimeout(this.timer)
    document.removeEventListener("visibilitychange", this.flush)
    window.removeEventListener("pagehide", this.flush)
  }

  // Bound to input on the composer fields.
  schedule() {
    clearTimeout(this.timer)
    this.timer = setTimeout(() => this.save(), this.delayValue)
  }

  flush() {
    if (document.visibilityState === "visible") return

    clearTimeout(this.timer)
    this.save()
  }

  async save() {
    const current = this.snapshot()
    if (current === this.lastSaved) return

    this.setStatus("Saving…")

    const response = await post(this.urlValue, {
      body: JSON.stringify({ draft: this.payload() }),
      contentType: "application/json",
      responseKind: "json"
    })

    if (!response.ok) {
      // lastSaved is left alone so the next edit retries this content
      // instead of treating it as already stored.
      this.setStatus("Not saved - will retry")
      return
    }

    const data = await response.json
    if (data.draft_message_id) {
      this.draftIdTarget.value = data.draft_message_id
      if (data.message_id) this.messageIdTarget.value = data.message_id
    }
    this.lastSaved = current
    // The time matters: without it the status is a constant string, and a
    // user cannot tell a save that just landed from one ten minutes old.
    this.setStatus(data.draft_message_id ? `Saved to Drafts ${this.timeOf(data.saved_at)}` : "")
  }

  // Everything the server needs: the typed content plus the identifiers
  // that thread this draft and name the revision it supersedes.
  payload() {
    return {
      ...this.snapshotFields(),
      message_id: this.messageIdTarget.value,
      draft_message_id: this.draftIdTarget.value
    }
  }

  // Only what the user can type. The draft id changes on every save and the
  // message id is filled in by the first one; including either would make
  // the content look different every time and autosave forever.
  snapshotFields() {
    return this.fieldTargets.reduce((acc, field) => {
      acc[field.dataset.draftField] = field.value
      return acc
    }, {})
  }

  snapshot() {
    return JSON.stringify(this.snapshotFields())
  }

  timeOf(iso) {
    const at = iso ? new Date(iso) : new Date()
    return at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }

  setStatus(text) {
    if (this.hasStatusTarget) this.statusTarget.textContent = text
  }
}
