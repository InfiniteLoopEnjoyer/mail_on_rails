import { Controller } from "@hotwired/stimulus"

// Reloads the <turbo-frame> it sits on every intervalValue ms - how the
// live connection pages stay live. Hidden tabs skip refreshes. The frame
// is server-rendered without a src, so the first refresh points it at
// the current page URL; after that Turbo's own reload() re-fetches it.
export default class extends Controller {
  static values = { interval: { type: Number, default: 5000 } }

  connect() {
    this.timer = setInterval(() => this.refresh(), this.intervalValue)
  }

  disconnect() {
    clearInterval(this.timer)
  }

  refresh() {
    if (document.hidden) return
    if (this.element.src) this.element.reload()
    else this.element.src = window.location.href
  }
}
