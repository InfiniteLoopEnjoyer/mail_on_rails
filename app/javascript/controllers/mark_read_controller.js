import { Controller } from "@hotwired/stimulus"
import { post } from "@rails/request.js"

// Rendered only when the page was served from a hover-prefetch (the message
// is still unseen); connecting means the user actually opened the message.
export default class extends Controller {
  static values = { url: String }

  connect() {
    post(this.urlValue)
  }
}
