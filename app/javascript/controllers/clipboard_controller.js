import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["source", "feedback"]

  async copy() {
    await navigator.clipboard.writeText(this.sourceTarget.textContent.trim())
    this.feedbackTarget.hidden = false
    clearTimeout(this.timeout)
    this.timeout = setTimeout(() => { this.feedbackTarget.hidden = true }, 2000)
  }

  disconnect() {
    clearTimeout(this.timeout)
  }
}
