require "nokogiri"

# Strict validation/sanitization for BIMI logos, applied both to logos
# fetched from remote senders (BimiIndicator) and to logos an operator
# uploads for a hosted domain (Domain#bimi_svg). SVG is a
# scripting-capable format rendered inside our webmail, so this is a
# security boundary, not a lint: the profile enforced here is the
# spirit of SVG Tiny PS (the BIMI profile) - static, self-contained
# vector art - and anything outside it is rejected rather than stripped
# (a "fixed" hostile file is still a hostile file).
#
# Rejected outright: oversize files, unparseable XML, DTDs (XXE),
# processing instructions, scripting/animation/interaction elements,
# event-handler attributes, raster/embedded content, and any reference
# that leaves the document (href/url() to anything but an internal #id).
module MailOnRails
  class BimiSvg
    class Invalid < StandardError; end

    MAX_BYTES = 32 * 1024 # the BIMI group's recommended ceiling

    FORBIDDEN_ELEMENTS = %w[
      script foreignObject image use a iframe embed object video audio
      animate animateMotion animateTransform animateColor set handler
      listener discard
    ].to_set.freeze

    # href/xlink:href may only point inside the document.
    REFERENCE_ATTRIBUTES = %w[href xlink:href].freeze

    # url(...) in styles/paint may only point inside the document.
    EXTERNAL_URL = /url\s*\(\s*['"]?\s*(?!#)/i

    # The sanitized (re-serialized) SVG, or raises Invalid.
    def self.sanitize(svg)
      raise Invalid, "logo is empty" if svg.to_s.strip.empty?
      raise Invalid, "logo exceeds #{MAX_BYTES / 1024} KB" if svg.to_s.bytesize > MAX_BYTES

      doc = parse(svg)
      raise Invalid, "root element is not <svg>" unless doc.root&.name == "svg"
      raise Invalid, "DTDs are not allowed" if doc.internal_subset || doc.external_subset
      raise Invalid, "processing instructions are not allowed" if doc.xpath("//processing-instruction()").any?

      doc.root.traverse do |node|
        check_element(node) if node.element?
      end
      doc.root.to_xml
    end

    def self.valid?(svg)
      sanitize(svg)
      true
    rescue Invalid
      false
    end

    def self.parse(svg)
      Nokogiri::XML(svg.to_s) { |config| config.strict.nonet }
    rescue Nokogiri::XML::SyntaxError => e
      raise Invalid, "not well-formed XML (#{e.message.to_s.truncate(80)})"
    end

    def self.check_element(node)
      name = node.name
      raise Invalid, "<#{name}> is not allowed" if FORBIDDEN_ELEMENTS.include?(name)

      if name == "style" && node.content.match?(/@import|#{EXTERNAL_URL.source}/i)
        raise Invalid, "<style> may not reference external content"
      end

      node.attribute_nodes.each do |attr|
        full_name = [ attr.namespace&.prefix, attr.name ].compact.join(":")
        raise Invalid, "event handler attribute #{full_name} is not allowed" if attr.name.match?(/\Aon/i)
        if REFERENCE_ATTRIBUTES.include?(full_name) && !attr.value.strip.start_with?("#")
          raise Invalid, "#{full_name} may only reference an internal #id"
        end
        raise Invalid, "external url() reference in #{full_name}" if attr.value.match?(EXTERNAL_URL)
      end
    end
  end
end
