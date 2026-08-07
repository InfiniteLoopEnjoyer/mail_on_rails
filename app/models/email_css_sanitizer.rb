# Reduces untrusted stylesheet text (the <style> blocks of HTML mail) to
# rules safe to re-emit inside the message iframe, so newsletters styled
# via stylesheet rules (rather than inline styles) keep their look.
#
# Policy, mirroring EmailHtmlSanitizer's stance on inline styles:
#   - qualified rules survive with their declarations scrubbed through
#     Loofah's CSS safelist (kills url(), expression(), position, behavior),
#     the same filter applied to style="" attributes
#   - @media survives with its rules recursively held to the same policy
#   - everything else - @import, @font-face, unknown at-rules - is dropped
#   - output is re-serialized from the Crass parse tree, never from the raw
#     text, and any chunk containing a literal "</" is dropped outright: the
#     result is embedded in a <style> element, where "</style" (including
#     one smuggled inside an attribute-selector string) would end the
#     element and turn the rest of the payload into markup
class EmailCssSanitizer
  # "<" never occurs in a selector we'd want (the child combinator is ">"),
  # and rejecting it wholesale blocks "</style" breakouts and CDO tokens.
  UNSAFE_SELECTOR = /</
  # @media preludes legitimately use "<" in range syntax ((400px <= width)),
  # so only the element-terminating sequence is refused there.
  UNSAFE_CSS = %r{</}

  def self.sanitize(css)
    new.sanitize(css)
  end

  def sanitize(css)
    css = css.to_s
    return "" if css.strip.empty?

    rules(Crass.parse(css)).join("\n")
  end

  private

  def rules(nodes)
    nodes.filter_map do |node|
      case node[:node]
      when :style_rule
        style_rule(node)
      when :at_rule
        media_rule(node) if node[:name].to_s.casecmp?("media")
      end
    end
  end

  def style_rule(rule)
    selector = rule[:selector][:value].to_s.strip
    return if selector.empty? || selector.match?(UNSAFE_SELECTOR)

    # The declarations were parsed by Crass already; stringify re-serializes
    # only those parsed nodes, then Loofah applies its property/keyword
    # safelist - the exact filter inline style="" attributes go through.
    declarations = Loofah::HTML5::Scrub.scrub_css(Crass::Parser.stringify(rule[:children]))
    return if declarations.empty? || declarations.match?(UNSAFE_CSS)

    "#{selector} { #{declarations} }"
  end

  def media_rule(rule)
    prelude = Crass::Parser.stringify(rule[:prelude], exclude_comments: true).strip
    return if prelude.empty? || prelude.match?(UNSAFE_CSS)

    inner = rules(Crass::Parser.parse_rules(rule[:block] || []))
    return if inner.empty?

    "@media #{prelude} {\n#{inner.join("\n")}\n}"
  end
end
