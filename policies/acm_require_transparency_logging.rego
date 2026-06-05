# METADATA
# title: ACM certificate must have transparency logging enabled
# description: Certificate transparency logging is required for ACM-issued certificates. Disabling it prevents detection of mis-issued certificates.
# custom:
#   controls:
#     - CC6.7
#     - CC7.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_transparency_logging

violation[{"id": "transparency_logging_disabled"}] if {
	input.transparency_logging_preference != "ENABLED"
}

title := "ACM certificate must have transparency logging enabled"
description := "Certificate transparency logging is required for ACM-issued certificates. Disabling it prevents detection of mis-issued certificates."

risk_templates := [{
	"name":            "ACM certificate transparency logging is disabled",
	"title":           "ACM certificate has transparency logging disabled",
	"statement":       "Certificate transparency logging is not enabled for this certificate. Without it, the certificate will not appear in public CT logs, preventing detection of mis-issued certificates by monitoring services.",
	"likelihood_hint": "medium",
	"impact_hint":     "medium",
	"violation_ids":   ["transparency_logging_disabled"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-778",
			"title":       "Insufficient Logging",
			"url":         "https://cwe.mitre.org/data/definitions/778.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title":       "Protection Mechanism Failure",
			"url":         "https://cwe.mitre.org/data/definitions/693.html"
		}
	],
	"remediation": {
		"title":       "Enable certificate transparency logging",
		"description": "Re-request the certificate with transparency logging enabled so that it is recorded in public CT logs and can be monitored for mis-issuance.",
		"tasks": [
			{"title": "Request a replacement ACM certificate with transparency logging set to ENABLED"},
			{"title": "Attach the new certificate to all resources currently using the non-logged certificate"},
			{"title": "Verify the new certificate appears in a public Certificate Transparency log (e.g. crt.sh)"},
			{"title": "Delete the certificate with logging disabled once all resources reference the replacement"}
		]
	}
}]
