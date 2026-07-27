import { Controller } from "@hotwired/stimulus"
import { post } from "@rails/request.js"
import { Turbo } from "@hotwired/turbo-rails"

// Runs the two WebAuthn ceremonies: register on the security page
// (TwoFactor::PasskeysController), authenticate on the login challenge
// (TwoFactor::ChallengesController). The server speaks the WebAuthn JSON
// wire format, so the browser's native parse*FromJSON / toJSON handle all
// base64url <-> ArrayBuffer conversion - no client library needed.
export default class extends Controller {
  static targets = ["error", "nickname"]
  static values = { optionsUrl: String, verifyUrl: String }

  register() {
    return this.#ceremony((options) =>
      navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })
    )
  }

  authenticate() {
    return this.#ceremony((options) =>
      navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) })
    )
  }

  async #ceremony(requestCredential) {
    this.#showError(null)
    if (!window.PublicKeyCredential?.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON) {
      return this.#showError("This browser doesn't support passkeys.")
    }

    const optionsResponse = await post(this.optionsUrlValue, { responseKind: "json" })
    if (!optionsResponse.ok) {
      return this.#showError("Couldn't start the passkey ceremony. Reload the page and try again.")
    }

    let credential
    try {
      credential = await requestCredential(await optionsResponse.json)
    } catch {
      return this.#showError("Passkey prompt was cancelled or failed.")
    }

    const body = { credential: credential.toJSON() }
    if (this.hasNicknameTarget) body.nickname = this.nicknameTarget.value

    const verifyResponse = await post(this.verifyUrlValue, {
      body: JSON.stringify(body), contentType: "application/json", responseKind: "json"
    })
    const result = await verifyResponse.json.catch(() => ({}))
    if (verifyResponse.ok && result.location) {
      Turbo.visit(result.location)
    } else {
      this.#showError(result.error || "Passkey verification failed.")
    }
  }

  #showError(message) {
    if (!this.hasErrorTarget) return
    this.errorTarget.textContent = message || ""
    this.errorTarget.hidden = !message
  }
}
