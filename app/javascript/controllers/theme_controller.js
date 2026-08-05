import { Controller } from "@hotwired/stimulus"
import { patch } from "@rails/request.js"

// The user's appearance (light/dark/system) and accent theme. The layout
// paints both onto <html> for a flash-free full load, but Turbo visits swap
// only <body> - so the authoritative copy rides here as Stimulus values,
// re-stamped onto <html> every time the body (and its values) change.
// Picker clicks update the values for instant feedback and PATCH the
// changed attribute to ThemesController. Lives on <body> so a "system"
// appearance tracks OS theme changes app-wide.
export default class extends Controller {
  static values = { url: String, appearance: String, accent: String }
  static targets = ["appearance", "accent"]

  initialize() {
    this.media = matchMedia("(prefers-color-scheme: dark)")
  }

  connect() {
    this.systemChanged = () => { if (this.appearanceValue === "system") this.apply() }
    this.media.addEventListener("change", this.systemChanged)
    this.apply()
  }

  disconnect() {
    this.media.removeEventListener("change", this.systemChanged)
  }

  appearanceValueChanged() { this.apply() }
  accentValueChanged() { this.apply() }

  // data-theme-value-param: "light" | "dark" | "system"
  setAppearance(event) {
    this.appearanceValue = event.params.value
    patch(this.urlValue, { body: { appearance: event.params.value } })
  }

  // data-theme-value-param: a User::ACCENT_THEMES key
  setAccent(event) {
    this.accentValue = event.params.value
    patch(this.urlValue, { body: { accent: event.params.value } })
  }

  apply() {
    const html = document.documentElement
    html.dataset.appearance = this.appearanceValue
    html.dataset.accent = this.accentValue
    html.classList.toggle("dark", this.appearanceValue === "dark" || (this.appearanceValue === "system" && this.media.matches))
    this.appearanceTargets.forEach(button => {
      button.ariaPressed = String(button.dataset.themeValueParam === this.appearanceValue)
    })
    this.accentTargets.forEach(button => {
      button.ariaPressed = String(button.dataset.themeValueParam === this.accentValue)
    })
  }
}
