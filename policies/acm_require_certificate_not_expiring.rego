# METADATA
# title: ACM certificate must not be expiring within the warning window
# description: Certificates expiring within expiry_warning_days days indicate a renewal risk that can cause service outages.
# custom:
#   controls:
#     - CC7.2
#     - CC9.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_certificate_not_expiring

violation[{"id": "certificate_expiring_soon"}] if {
	warning_days := data.expiry_warning_days
	deadline_ns := time.now_ns() + (warning_days * 24 * 60 * 60 * 1000000000)
	expiry_ns := time.parse_rfc3339_ns(input.not_after)
	expiry_ns < deadline_ns
}

title := "ACM certificate must not be expiring within the warning window"
description := "Certificates expiring within expiry_warning_days days indicate a renewal risk that can cause service outages."

risk_templates := [{
	"name":            "ACM certificate is expiring within the warning window",
	"title":           "ACM certificate is approaching its expiry date",
	"statement":       "The certificate will expire within the configured warning window. If not renewed before expiry, HTTPS endpoints will serve an invalid certificate, causing browser errors and potential service outages.",
	"likelihood_hint": "high",
	"impact_hint":     "high",
	"violation_ids":   ["certificate_expiring_soon"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-324",
			"title":       "Use of a Key Past its Expiration Date",
			"url":         "https://cwe.mitre.org/data/definitions/324.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-298",
			"title":       "Improper Validation of Certificate Expiration",
			"url":         "https://cwe.mitre.org/data/definitions/298.html"
		}
	],
	"remediation": {
		"title":       "Renew or replace the certificate before it expires",
		"description": "Trigger ACM renewal or request a new certificate and update all attached resources before the expiry date to prevent service disruption.",
		"tasks": [
			{"title": "Check whether the certificate is eligible for automatic renewal in ACM"},
			{"title": "If not eligible, request a new certificate with the same domain names"},
			{"title": "Update all resources (load balancers, CloudFront, API Gateway) to reference the renewed certificate"},
			{"title": "Verify the renewed certificate is active and serving HTTPS traffic before the old certificate expires"}
		]
	}
}]
