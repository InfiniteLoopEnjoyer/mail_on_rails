require "test_helper"

# The sanitizer is the first layer of the HTML-mail defense (the sandboxed
# iframe in the view is the second), so these tests pin the classic webmail
# attack payloads: script injection in its many syntactic disguises, CSS
# tricks, and image sources that would leak or execute.
class EmailHtmlSanitizerTest < ActiveSupport::TestCase
  def sanitize(html, **options)
    EmailHtmlSanitizer.sanitize(html, **options)
  end

  test "keeps formatting markup" do
    result = sanitize("<p>Hello <b>world</b></p><table><tr><td bgcolor=\"#eee\" width=\"100\">cell</td></tr></table>")

    assert_includes result.html, "<b>world</b>"
    assert_includes result.html, '<td bgcolor="#eee" width="100">cell</td>'
  end

  test "prunes script elements with their contents" do
    result = sanitize("<p>hi</p><script>alert(1)</script>")

    assert_includes result.html, "<p>hi</p>"
    assert_not_includes result.html, "alert"
  end

  test "prunes svg, forms, frames, and metadata elements" do
    html = "<svg><script>alert(1)</script></svg>" \
           '<form action="https://evil.test"><input name="password"></form>' \
           '<iframe src="https://evil.test"></iframe>' \
           '<base href="https://evil.test/">' \
           "<p>survivor</p>"
    result = sanitize(html)

    assert_equal "<p>survivor</p>", result.html
  end

  test "scrubs style blocks and inline styles through the same CSS safelist" do
    html = "<style>body { background: url(https://evil.test/x) }</style>" \
           '<div style="color: red; position: fixed; background-image: url(https://t.test/p); width: expression(alert(1))">x</div>'
    result = sanitize(html)

    assert_not_includes result.html, "evil.test"
    assert_not_includes result.html, "position"
    assert_not_includes result.html, "url("
    assert_not_includes result.html, "expression"
    assert_includes result.html, 'style="color:red;"'
  end

  # The <style> markup slot is pruned from the body, but its scrubbed rules
  # come back as one style element at the top of the fragment - newsletters
  # styled via stylesheet rules keep their look (EmailCssSanitizer has the
  # CSS-level cases).
  test "style rules survive scrubbed, from head and body alike" do
    html = "<html><head><style>p { color: blue; background: url(//evil.test/x) }</style></head>" \
           "<body><style>.footer { text-align: center }</style><p>hi</p></body></html>"
    result = sanitize(html)

    assert_includes result.html, "p { color:blue; }"
    assert_includes result.html, ".footer { text-align:center; }"
    assert_not_includes result.html, "evil.test"
    assert_select_html result.html, "style"
    assert_select_html result.html, "p"
  end

  test "a style element's media attribute becomes an @media wrapper" do
    result = sanitize('<style media="only screen and (max-width: 600px)">p { color: red }</style><p>x</p>')

    assert_includes result.html, "@media only screen and (max-width: 600px) {"
    assert_includes result.html, "p { color:red; }"
  end

  test "a stylesheet with no surviving rules leaves no style element behind" do
    result = sanitize("<style>@import url(https://evil.test/x.css);</style><p>x</p>")

    assert_equal "<p>x</p>", result.html
  end

  test "unwraps unknown tags keeping their text" do
    result = sanitize("<blink>deal <marquee>expires</marquee> soon</blink>")

    assert_equal "deal expires soon", result.html
  end

  test "removes comments" do
    result = sanitize("<p>a</p><!-- if lt IE 9 --><p>b</p>")

    assert_not_includes result.html, "IE 9"
  end

  test "strips event handler attributes" do
    result = sanitize('<img src="https://x.test/a.png" onerror="alert(1)" onload="alert(2)">')

    assert_not_includes result.html, "onerror"
    assert_not_includes result.html, "onload"
  end

  test "links keep http/https/mailto and open in a new tab" do
    result = sanitize('<a href="https://example.test/x">a</a><a href="mailto:bob@example.test">b</a>')

    assert_select_html result.html, 'a[href="https://example.test/x"][target="_blank"][rel="noopener noreferrer"]'
    assert_select_html result.html, 'a[href="mailto:bob@example.test"]'
  end

  test "javascript and relative hrefs are removed, obfuscated or not" do
    html = '<a href="javascript:alert(1)">a</a>' \
           "<a href=\" jAvAsCrIpT:alert(1)\">b</a>" \
           "<a href=\"java\nscript:alert(1)\">c</a>" \
           '<a href="/accounts">d</a>' \
           '<a href="data:text/html,<script>alert(1)</script>">e</a>'
    result = sanitize(html)

    assert_not_includes result.html, "href"
    assert_not_includes result.html, "script"
  end

  test "remote images are replaced with a placeholder and counted" do
    result = sanitize('<img src="https://tracker.test/pixel.png" width="1">')

    assert_equal 1, result.remote_images
    assert_not_includes result.html, "tracker.test"
    assert_includes result.html, EmailHtmlSanitizer::BLOCKED_PIXEL
    assert_includes result.html, 'width="1"'
  end

  test "remote images load when the reader opted in" do
    result = sanitize('<img src="https://cdn.test/logo.png">', allow_remote_images: true)

    assert_equal 1, result.remote_images
    assert_includes result.html, "https://cdn.test/logo.png"
  end

  test "scheme-relative image URLs count as remote" do
    result = sanitize('<img src="//tracker.test/pixel.png">')

    assert_equal 1, result.remote_images
    assert_not_includes result.html, "tracker.test"
  end

  test "cid images are inlined as data URIs from the message's own parts" do
    images = { "pic1" => EmailHtmlSanitizer::InlineImage.new(content_type: "image/png", data: "PNGBYTES") }
    result = sanitize('<img src="cid:pic1" alt="chart">', inline_images: images)

    assert_includes result.html, "data:image/png;base64,#{Base64.strict_encode64("PNGBYTES")}"
    assert_equal 0, result.remote_images
  end

  test "cid images without a matching part are dropped" do
    result = sanitize('<p>x</p><img src="cid:missing">')

    assert_equal "<p>x</p>", result.html
  end

  test "data URIs survive only for image types" do
    html = '<img src="data:image/gif;base64,R0lGODlhAQABAA==">' \
           '<img src="data:text/html;base64,PHNjcmlwdD4=">'
    result = sanitize(html)

    assert_includes result.html, "data:image/gif"
    assert_not_includes result.html, "data:text/html"
  end

  test "a link whose text claims a different host gets the real destination stamped on it" do
    result = sanitize('<a href="https://evil.guy.com/some_path?some_param=poo">https://innocent.website.com</a>')

    assert_equal 1, result.deceptive_links
    assert_includes result.html, ">https://innocent.website.com</a>"
    assert_includes result.html, "[actually links to https://evil.guy.com/some_path?some_param=poo]"
  end

  test "bare-domain link text is held to the same claim" do
    result = sanitize('<a href="https://evil.test/login">paypal.com/security</a>')

    assert_equal 1, result.deceptive_links
    assert_includes result.html, "[actually links to https://evil.test/login]"
  end

  test "an @ in the link text cannot smuggle a matching host past the check" do
    result = sanitize('<a href="https://evil.test/x">https://innocent.test@evil.test</a>')

    assert_equal 1, result.deceptive_links
    assert_includes result.html, "[actually links to https://evil.test/x]"
  end

  test "very long deceptive URLs are truncated in the marker" do
    href = "https://evil.test/#{"a" * 300}"
    result = sanitize(%(<a href="#{href}">https://innocent.test</a>))

    assert_equal 1, result.deceptive_links
    marker = Nokogiri::HTML5.fragment(result.html).css("span").first.text
    assert marker.end_with?("...]")
    assert_operator marker.length, :<=, 225
  end

  test "matching, www-variant, and same-site subdomain links stay unmarked" do
    html = '<a href="https://example.test/page">https://example.test/page</a>' \
           '<a href="https://www.example.test/">example.test</a>' \
           '<a href="https://click.example.test/track?u=1">https://example.test/article</a>'
    result = sanitize(html)

    assert_equal 0, result.deceptive_links
    assert_not_includes result.html, "actually links to"
  end

  test "non-URL link text makes no claim to check" do
    result = sanitize('<a href="https://anywhere.test/x">Click here to view your document</a>')

    assert_equal 0, result.deceptive_links
  end

  test "mailto links are not checked for host claims" do
    result = sanitize('<a href="mailto:bob@example.test">https://example.test</a>')

    assert_equal 0, result.deceptive_links
  end

  test "a full document is reduced to its body content plus scrubbed styles" do
    html = "<html><head><title>t</title><style>p{color:blue}</style></head><body><p>content</p></body></html>"
    result = sanitize(html)

    assert result.html.end_with?("<p>content</p>")
    assert_includes result.html, "p { color:blue; }"
    assert_not_includes result.html, "<title>"
  end

  private

  # assert_select against a detached fragment.
  def assert_select_html(html, selector)
    assert_not_empty Nokogiri::HTML5.fragment(html).css(selector),
                     "expected #{selector.inspect} in #{html.inspect}"
  end
end
