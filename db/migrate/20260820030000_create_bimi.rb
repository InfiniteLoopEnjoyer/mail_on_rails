# frozen_string_literal: true

# BIMI (Brand Indicators for Message Identification), both directions:
#
#   bimi_indicators - the receiver-side cache: one row per sender domain
#     whose logo the webmail may display, holding the DMARC-gated lookup
#     verdict and the sanitized SVG (RefreshBimiIndicatorJob writes it).
#   domains.bimi_svg - the sender side: an operator-uploaded logo for a
#     hosted domain, served by the engine at /bimi/<domain>/logo.svg and
#     pointed at by the self-asserted default._bimi TXT DnsPublisher
#     publishes. Sanitized on save (Domain's validation).
class CreateBimi < ActiveRecord::Migration[8.1]
  def change
    create_table "mail_on_rails_bimi_indicators" do |t|
      t.string :domain, null: false
      t.string :status, null: false, default: "pending" # pending/pass/none/declined/fail
      t.text :svg                                       # sanitized; present only on pass
      t.boolean :evidence, null: false, default: false  # a= (VMC/CMC) present - recorded, not validated
      t.string :error
      t.datetime :checked_at

      t.timestamps

      t.index [ "domain" ], name: "index_bimi_indicators_on_domain", unique: true
      t.index [ "checked_at" ], name: "index_bimi_indicators_on_checked_at"
    end

    add_column :mail_on_rails_domains, :bimi_svg, :text
    # An earlier migration in the same run used the model (unsubscribe
    # account backfill), fixing its column cache pre-bimi_svg.
    MailOnRails::Domain.reset_column_information
  end
end
