module EmailMessagesHelper
  # The document shell for the message iframe's srcdoc. HTML mail is written
  # against a white canvas, so the shell pins light colors even when the app
  # chrome is in dark mode; the sanitized fragment carries no <head> of its
  # own (EmailHtmlSanitizer keeps only body content).
  def email_html_document(html)
    <<~HTML
      <!doctype html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="margin: 8px; background: #fff; color: #111; font-family: system-ui, sans-serif; font-size: 14px; line-height: 1.5; overflow-wrap: break-word">
      #{html}
      </body>
      </html>
    HTML
  end
end
