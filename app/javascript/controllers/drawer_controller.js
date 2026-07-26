import { Controller } from "@hotwired/stimulus"

// Mobile nav drawer (below lg). On lg+ the panel is pinned open via
// lg:translate-x-0 and this controller is effectively inert.
export default class extends Controller {
  static targets = ["panel", "backdrop"]

  connect() {
    // Close before Turbo caches so restored snapshots never flash open.
    this.closeBeforeCache = () => this.close()
    document.addEventListener("turbo:before-cache", this.closeBeforeCache)
  }

  disconnect() {
    document.removeEventListener("turbo:before-cache", this.closeBeforeCache)
  }

  toggle() {
    this.open ? this.close() : this.show()
  }

  show() {
    this.panelTarget.classList.remove("-translate-x-full")
    this.backdropTarget.classList.remove("hidden")
    document.body.classList.add("overflow-hidden")
  }

  close() {
    this.panelTarget.classList.add("-translate-x-full")
    this.backdropTarget.classList.add("hidden")
    document.body.classList.remove("overflow-hidden")
  }

  get open() {
    return !this.panelTarget.classList.contains("-translate-x-full")
  }
}
