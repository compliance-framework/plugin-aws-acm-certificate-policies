# METADATA
# title: Non-ISSUED certificate must not be attached to any AWS resource
# description: An expired or revoked certificate still appearing in in_use_by indicates
#              that the access-removal trigger failed to propagate to the endpoint.
# custom:
#   controls:
#     - CC6.2
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_no_expired_cert_in_use

violation[{"id": "expired_certificate_in_use", "resource": resource}] if {
	not input.status in data.approved_certificate_statuses
	resource := input.in_use_by[_]
}

title := "Non-ISSUED certificate must not be attached to any AWS resource"
description := "An expired or revoked certificate still appearing in in_use_by indicates that the access-removal trigger failed to propagate to the endpoint."

risk_templates := [{
	"name":            "ACM expired or revoked certificate is still attached to an AWS resource",
	"title":           "ACM non-ISSUED certificate is still in use",
	"statement":       "An expired or revoked certificate is still attached to one or more AWS resources. This will cause HTTPS connections to fail or serve an invalid certificate, and indicates the access-removal process did not complete.",
	"likelihood_hint": "critical",
	"impact_hint":     "critical",
	"violation_ids":   ["expired_certificate_in_use"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-295",
			"title":       "Improper Certificate Validation",
			"url":         "https://cwe.mitre.org/data/definitions/295.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-298",
			"title":       "Improper Validation of Certificate Expiration",
			"url":         "https://cwe.mitre.org/data/definitions/298.html"
		}
	],
	"remediation": {
		"title":       "Immediately remove the non-ISSUED certificate from all attached resources",
		"description": "Replace the expired or revoked certificate with a valid one on all attached resources to restore secure HTTPS connectivity.",
		"tasks": [
			{"title": "Identify all resources listed in the certificate's in_use_by field"},
			{"title": "Obtain or request a valid replacement certificate for the same domain names"},
			{"title": "Attach the replacement certificate to each affected resource"},
			{"title": "Confirm that HTTPS is serving the new certificate and no resources reference the expired certificate"}
		]
	}
}]
