# frozen_string_literal: true

# Builds an edge-stamped inbound mail carrying a minimal DMARC aggregate
# report for the example.test domain (4 aligned messages from one IP).
module DmarcReportMailHelper
  REPORT_XML = <<~XML
    <?xml version="1.0"?>
    <feedback>
      <report_metadata>
        <org_name>google.com</org_name>
        <report_id>rid-1</report_id>
        <date_range><begin>1753142400</begin><end>1753228800</end></date_range>
      </report_metadata>
      <policy_published><domain>example.test</domain></policy_published>
      <record>
        <row>
          <source_ip>198.51.100.10</source_ip>
          <count>4</count>
          <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
        </row>
      </record>
    </feedback>
  XML

  def report_mail(to)
    mail = Mail.new
    mail.from = "noreply-dmarc-support@google.com"
    mail.to = to
    mail.subject = "Report domain: example.test"
    mail.body = "attached"
    mail.add_file filename: "google.com!example.test!1!2.xml", content: REPORT_XML
    "Return-Path: <noreply-dmarc-support@google.com>\r\n" \
      "X-Original-To: #{to}\r\n" \
      "X-MailOnRails-Authenticated: no\r\n" + mail.to_s
  end
end
