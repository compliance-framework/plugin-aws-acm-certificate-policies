# METADATA
# title: ACM-issued certificate must be eligible for automatic renewal when nearing expiry
# description: Certificates with renewal_eligibility=INELIGIBLE require manual action to renew.
#              Flag them early to avoid lapses in the access-removal and re-issuance process.
# custom:
#   controls:
#     - CC6.2
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_renewal_eligibility

violation[{"id": "certificate_not_eligible_for_renewal"}] if {
	input.type == "AMAZON_ISSUED"
	input.status == "ISSUED"
	input.renewal_eligibility != "ELIGIBLE"
	warning_days := data.renewal_warning_days
	now_ns := time.now_ns()
	deadline_ns := now_ns + (warning_days * 24 * 60 * 60 * 1000000000)
	expiry_ns := time.parse_rfc3339_ns(input.not_after)
	expiry_ns >= now_ns
	expiry_ns <= deadline_ns
}

title := "ACM-issued certificate must be eligible for automatic renewal when nearing expiry"
description := "Certificates with renewal_eligibility=INELIGIBLE require manual action to renew. Flag them early to avoid lapses in the access-removal and re-issuance process."

risk_templates := [{
	"name":            "ACM certificate is not eligible for automatic renewal",
	"title":           "ACM certificate cannot be automatically renewed",
	"statement":       "The certificate is approaching expiry but is ineligible for automatic renewal, requiring manual intervention to avoid a service outage when the certificate expires.",
	"likelihood_hint": "high",
	"impact_hint":     "high",
	"violation_ids":   ["certificate_not_eligible_for_renewal"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-324",
			"title":       "Use of a Key Past its Expiration Date",
			"url":         "https://cwe.mitre.org/data/definitions/324.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title":       "Protection Mechanism Failure",
			"url":         "https://cwe.mitre.org/data/definitions/693.html"
		}
	],
	"remediation": {
		"title":       "Investigate and resolve the renewal eligibility block",
		"description": "Determine why the certificate is INELIGIBLE for renewal and take corrective action before the expiry deadline to prevent service disruption.",
		"tasks": [
			{"title": "Check the ACM console for the reason the certificate is INELIGIBLE (e.g. DNS CNAME records missing or changed)"},
			{"title": "Restore or re-add the required DNS CNAME validation records if they were removed"},
			{"title": "If DNS records cannot be restored, request a new certificate with DNS validation and migrate attached resources"},
			{"title": "Confirm renewal eligibility is restored and that ACM has successfully renewed or a replacement is in place"}
		]
	}
}]
