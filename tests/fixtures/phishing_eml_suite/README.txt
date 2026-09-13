Synthetic .eml phishing test suite

All domains are reserved/obviously synthetic test domains. No real credentials, malware, or live payment details are included.

Files:
01_display_name_spoof.eml       - From display-name spoofing + Reply-To mismatch
02_credential_harvest.eml      - Credential-harvest wording + suspicious login URL
03_invoice_attachment.eml      - Double-extension executable attachment + payment pressure
04_lookalike_domain.eml        - Lookalike brand/domain signal
05_bec_reply_to_mismatch.eml   - BEC-style bank-detail request + Received/Return-Path mismatch
06_uri_obfuscation.eml         - Userinfo (@) URL obfuscation
07_payroll_redirect.eml        - Redirector + nested destination URL
08_unicode_lookalike.eml       - Punycode / IDN lookalike handling

Suggested detector labels:
- phishing
- business_email_compromise
- credential_harvesting
- suspicious_attachment
- spoofing
- malicious_or_suspicious_url
- header_anomaly
