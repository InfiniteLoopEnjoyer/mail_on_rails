# frozen_string_literal: true

require "mail_on_rails/rspamd_analyzer"

# Swaps MailOnRails::RspamdAnalyzer's module functions for the block's
# duration, then restores the originals (same pattern as ClamavStubHelper).
# `analyze:` takes a Result or a callable receiving (raw, **facts); pass a
# raising callable to assert a path must NOT analyze.
module RspamdStubHelper
  def with_rspamd(enabled:, analyze: nil)
    singleton = MailOnRails::RspamdAnalyzer.singleton_class
    original_enabled = MailOnRails::RspamdAnalyzer.method(:enabled?)
    original_analyze = MailOnRails::RspamdAnalyzer.method(:analyze)
    singleton.define_method(:enabled?) { enabled }
    singleton.define_method(:analyze) { |raw, **facts| analyze.respond_to?(:call) ? analyze.call(raw, **facts) : analyze }
    yield
  ensure
    singleton.define_method(:enabled?, original_enabled)
    singleton.define_method(:analyze, original_analyze)
  end
end
