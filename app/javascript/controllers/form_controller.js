import { Controller } from "@hotwired/stimulus"

// Submits the surrounding form from a data-action; replaces inline on*
// handler attributes, which the CSP forbids.
export default class extends Controller {
  submit() {
    this.element.requestSubmit()
  }
}
