require "test_helper"

# Stylesheet scrubbing for the <style> blocks of HTML mail. The output is
# re-embedded in a <style> element inside the message iframe, so beyond the
# usual CSS safelist the sanitizer must never emit a literal "</" - the
# sequence that would terminate the element and turn the rest of an
# attacker's stylesheet into markup.
class EmailCssSanitizerTest < ActiveSupport::TestCase
  def sanitize(css)
    EmailCssSanitizer.sanitize(css)
  end

  test "keeps qualified rules with safe declarations" do
    css = "p { color: blue; font-weight: bold } .footer td { text-align: center }"

    result = sanitize(css)

    assert_includes result, "p { color:blue;font-weight:bold; }"
    assert_includes result, ".footer td { text-align:center; }"
  end

  test "drops unsafe declarations but keeps the rule's safe ones" do
    result = sanitize("p { color: red; background: url(https://evil.test/x); width: expression(alert(1)) }")

    assert_includes result, "color:red;"
    assert_not_includes result, "url("
    assert_not_includes result, "evil.test"
    assert_not_includes result, "expression"
  end

  test "a rule with no surviving declarations is dropped entirely" do
    assert_equal "", sanitize("p { background: url(https://evil.test/x) }")
  end

  test "recurses into media queries" do
    css = "@media only screen and (max-width: 600px) { .col { width: 100% } p { background: url(//e.test) } }"

    result = sanitize(css)

    assert_includes result, "@media only screen and (max-width: 600px) {"
    assert_includes result, ".col { width:100%; }"
    assert_not_includes result, "url("
  end

  test "an emptied media query is dropped with its prelude" do
    assert_equal "", sanitize("@media print { p { background: url(//evil.test/x) } }")
  end

  test "drops import, font-face, and unknown at-rules" do
    css = "@import url(https://evil.test/steal.css); " \
          "@font-face { font-family: x; src: url(https://evil.test/f.woff) } " \
          "@keyframes slide { from { left: 0 } } " \
          "p { color: green }"

    result = sanitize(css)

    assert_equal "p { color:green; }", result
    assert_not_includes result, "evil.test"
  end

  test "a selector cannot smuggle a style-element breakout" do
    result = sanitize(%q{x</style><script>alert(1)</script> { color: red } p { color: blue }})

    assert_not_includes result, "</"
    assert_not_includes result, "script"
    assert_includes result, "p { color:blue; }"
  end

  test "an attribute-selector string cannot smuggle a breakout either" do
    result = sanitize(%q{a[title="</style><script>alert(1)</script>"] { color: red }})

    assert_not_includes result, "</"
    assert_not_includes result, "script"
  end

  test "comments are not carried into the output" do
    result = sanitize("p { color: red } /* sneaky </style> */")

    assert_not_includes result, "sneaky"
    assert_not_includes result, "</"
  end

  test "blank and nil input come back empty" do
    assert_equal "", sanitize(nil)
    assert_equal "", sanitize("   ")
  end
end
