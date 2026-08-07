require "base64"

# Reduces untrusted HTML mail to markup safe enough to embed in the message
# page. This is the first of two independent layers: the view additionally
# renders the result inside a sandboxed iframe (opaque origin, no scripts),
# so a sanitizer miss still cannot run code or touch the session.
#
# Policy:
#   - allowlisted tags survive; dangerous ones (script, forms, frames,
#     svg/mathml, media) are pruned with their contents; anything else is
#     unwrapped so its text remains readable
#   - allowlisted attributes survive; inline style is scrubbed through
#     Loofah's CSS safelist (kills url(), expression(), position, behavior)
#   - <style> blocks (head and body alike) are reduced by EmailCssSanitizer
#     to safelist-scrubbed rules and re-emitted as one <style> element at
#     the top of the fragment, so stylesheet-styled newsletters keep their
#     look without keeping their tricks
#   - links keep only absolute http/https/mailto/tel targets and always open
#     in a new tab; a link whose visible text reads like a URL on a different
#     host than its href gets the real destination stamped next to it (the
#     classic phishing tell: text says innocent.example, href says otherwise)
#   - cid: images are inlined as data: URIs from the message's own parts (no
#     extra requests, works inside the opaque-origin iframe); remote images
#     are swapped for a transparent pixel unless the reader opted in, since
#     loading them tells the sender when and where the mail was read
class EmailHtmlSanitizer
  Result = Data.define(:html, :remote_images, :deceptive_links)
  InlineImage = Data.define(:content_type, :data)

  ALLOWED_TAGS = %w[
    a abbr b big blockquote br caption center cite code col colgroup dd del
    dfn div dl dt em figcaption figure font h1 h2 h3 h4 h5 h6 hr i img ins
    kbd li mark ol p pre q s samp small span strike strong sub sup table
    tbody td tfoot th thead tr tt u ul var wbr
  ].to_set.freeze

  # Removed with their entire contents - either executable/interactive, or
  # text that only makes sense to a machine (fallback markup). style is
  # pruned here too, but only after its text was collected for
  # EmailCssSanitizer - the markup slot goes, the (scrubbed) rules stay.
  PRUNED_TAGS = %w[
    script style noscript template iframe frame frameset object embed applet
    form button input select option textarea label base link meta title head
    svg math audio video source track picture canvas map area dialog slot
  ].to_set.freeze

  ALLOWED_ATTRIBUTES = %w[
    align alt bgcolor border cellpadding cellspacing color colspan dir height
    href hspace lang nowrap rowspan span src style summary title valign
    vspace width
  ].to_set.freeze

  LINK_SCHEMES = /\A(?:https?:|mailto:|tel:)/i
  REMOTE_IMAGE = %r{\A(?:https?:)?//}i
  DATA_IMAGE = %r{\Adata:image/(?:png|gif|jpe?g|webp|bmp);}i

  BLOCKED_PIXEL = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7".freeze

  # inline_images maps a Content-ID (without angle brackets) to an
  # InlineImage; pass only images the message is vouched for (see
  # EmailMessage#inline_images).
  def self.sanitize(html, inline_images: {}, allow_remote_images: false)
    new(inline_images: inline_images, allow_remote_images: allow_remote_images).sanitize(html)
  end

  def initialize(inline_images:, allow_remote_images:)
    @inline_images = inline_images
    @allow_remote_images = allow_remote_images
    @remote_images = 0
    @deceptive_links = 0
  end

  def sanitize(html)
    document = Loofah.html5_document(html.to_s)
    body = document.at_xpath("//body")
    return Result.new(html: "", remote_images: 0, deceptive_links: 0) unless body

    # Collected document-wide before the scrub: newsletters put their
    # stylesheet in <head>, which the body extraction would never see, and
    # the scrub below prunes the <style> elements themselves.
    stylesheet = sanitize_stylesheets(document)
    scrub(body)
    expose_deceptive_links(body)
    Result.new(html: stylesheet + body.inner_html,
               remote_images: @remote_images, deceptive_links: @deceptive_links)
  end

  private

  # One scrubbed <style> element for the whole message, or "" when nothing
  # survives. A style element's media attribute scopes it in HTML, so its
  # rules are wrapped in the equivalent @media to keep that meaning.
  def sanitize_stylesheets(document)
    css = document.css("style").filter_map do |style|
      media = style["media"].to_s.strip
      text = media.empty? ? style.text : "@media #{media} { #{style.text} }"
      sanitized = EmailCssSanitizer.sanitize(text)
      sanitized unless sanitized.empty?
    end.join("\n")
    css.empty? ? "" : "<style>\n#{css}\n</style>"
  end

  def scrub(node)
    node.children.to_a.each do |child|
      unless child.element?
        child.remove unless child.text?
        next
      end

      name = child.name.downcase
      if PRUNED_TAGS.include?(name)
        child.remove
      elsif ALLOWED_TAGS.include?(name)
        scrub_attributes(child)
        scrub(child) if child.parent # scrub_attributes drops unusable imgs
      else
        scrub(child)
        child.replace(child.children)
      end
    end
  end

  def scrub_attributes(element)
    element.attribute_nodes.each do |attribute|
      element.remove_attribute(attribute.name) unless ALLOWED_ATTRIBUTES.include?(attribute.name.downcase)
    end

    scrub_style(element)
    case element.name.downcase
    when "a" then scrub_link(element)
    when "img" then scrub_image(element)
    end
  end

  def scrub_style(element)
    style = element["style"]
    return if style.nil?

    scrubbed = Loofah::HTML5::Scrub.scrub_css(style)
    scrubbed.empty? ? element.remove_attribute("style") : element["style"] = scrubbed
  end

  def scrub_link(element)
    if element["href"].to_s.strip.match?(LINK_SCHEMES)
      # The iframe sandbox only permits navigation via popup, so every link
      # opens a fresh, unsandboxed tab without reaching the app's own tab.
      element["target"] = "_blank"
      element["rel"] = "noopener noreferrer"
    else
      element.remove_attribute("href")
    end
  end

  def scrub_image(element)
    src = element["src"].to_s.strip
    case src
    when /\Acid:/i
      image = @inline_images[src.sub(/\Acid:/i, "")]
      image ? element["src"] = data_uri(image) : element.remove
    when REMOTE_IMAGE
      @remote_images += 1
      unless @allow_remote_images
        element["src"] = BLOCKED_PIXEL
        element["title"] = "Remote image blocked"
      end
    when DATA_IMAGE
      # already self-contained and image-typed; keep as-is
    else
      # relative URLs, javascript:, data:text/html, ... - nothing safe to show
      element.remove
    end
  end

  def data_uri(image)
    "data:#{image.content_type};base64,#{Base64.strict_encode64(image.data)}"
  end

  # A link whose visible text reads like a URL is a claim about where it
  # goes; when the claimed host isn't the href's host (allowing www./
  # subdomain variance, so newsletter click-tracking on the same site stays
  # quiet), stamp the real destination right next to the text. Runs after
  # scrubbing so the text judged is the text the reader will actually see.
  def expose_deceptive_links(body)
    body.css("a[href]").each do |link|
      next unless link["href"].to_s.match?(/\Ahttps?:/i)

      claimed = claimed_host(link.text)
      actual = URI.parse(link["href"]).host rescue nil
      next if claimed.nil? || hosts_match?(claimed, actual)

      @deceptive_links += 1
      marker = Nokogiri::XML::Node.new("span", body.document)
      marker["style"] = "color:#b91c1c;font-weight:bold;overflow-wrap:anywhere;"
      marker.content = " [actually links to #{link["href"].truncate(200)}]"
      link.add_next_sibling(marker)
    end
  end

  URL_LIKE_TEXT = %r{\A(?:https?://|www\.)\S+\z|\A[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/?#]\S*)?\z}i

  # The host a reader would take the text to mean, nil when the text doesn't
  # read as a URL at all. Everything up to the first path/query/port stops
  # the host; anything from an @ on is cut because the eye reads what comes
  # before it ("https://innocent.test@evil.test" claims innocent.test).
  def claimed_host(text)
    text = text.strip.sub(/[.,;:!)]+\z/, "")
    return nil unless text.match?(URL_LIKE_TEXT)

    text.sub(%r{\Ahttps?://}i, "")[%r{\A[^/?\#:@]+}]&.downcase
  end

  def hosts_match?(claimed, actual)
    return false if actual.nil?

    claimed = claimed.delete_prefix("www.")
    actual = actual.downcase.delete_prefix("www.")
    claimed == actual || actual.end_with?(".#{claimed}") || claimed.end_with?(".#{actual}")
  end
end
