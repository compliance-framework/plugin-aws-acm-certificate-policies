# METADATA
# title: ACM certificate must have an approved status
# description: Certificates must have a status listed in approved_certificate_statuses. Any status not explicitly approved, including PENDING_VALIDATION and INACTIVE, is a violation.
# custom:
#   controls:
#     - CC6.1
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_valid_status

violation[{"id": "certificate_status_not_approved"}] if {
	not input.status in data.approved_certificate_statuses
}

title := "ACM certificate must have an approved status"
description := "Certificates must have a status listed in approved_certificate_statuses. Any status not explicitly approved, including PENDING_VALIDATION and INACTIVE, is a violation."

risk_templates := [{
	"name":            "ACM certificate does not have an approved status",
	"title":           "ACM certificate has a non-approved status",
	"statement":       "The certificate status is not in the approved list, indicating a validation failure, pending issuance, or inactive state that means the certificate is not ready for use.",
	"likelihood_hint": "medium",
	"impact_hint":     "high",
	"violation_ids":   ["certificate_status_not_approved"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-295",
			"title":       "Improper Certificate Validation",
			"url":         "https://cwe.mitre.org/data/definitions/295.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title":       "Protection Mechanism Failure",
			"url":         "https://cwe.mitre.org/data/definitions/693.html"
		}
	],
	"remediation": {
		"title":       "Investigate and resolve the certificate status",
		"description": "Determine the reason for the non-approved status and take corrective action to bring the certificate to an approved state or replace it.",
		"tasks": [
			{"title": "Check the ACM console for the reason the certificate is not in an approved status"},
			{"title": "For PENDING_VALIDATION: add the required DNS or email validation records to complete issuance"},
			{"title": "For FAILED or REVOKED: request a new certificate and update all attached resources"},
			{"title": "For INACTIVE: determine whether the certificate is still needed and either activate or delete it"}
		]
	}
}]
