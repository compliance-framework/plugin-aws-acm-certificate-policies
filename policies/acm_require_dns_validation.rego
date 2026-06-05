# METADATA
# title: ACM certificate must use an approved domain validation method
# description: Email-based validation requires manual intervention and creates availability risk. DNS validation enables automatic renewal.
# custom:
#   controls:
#     - CC9.1
#     - A1.2
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_dns_validation

violation[{"id": "domain_validation_method_not_approved", "domain_name": dvo.domain_name}] if {
	some dvo in input.domain_validation_options
	not dvo.validation_method in data.approved_validation_methods
}

title := "ACM certificate must use an approved domain validation method"
description := "Email-based validation requires manual intervention and creates availability risk. DNS validation enables automatic renewal."

risk_templates := [{
	"name":            "ACM certificate domain validation method is not approved",
	"title":           "ACM certificate uses a non-approved domain validation method",
	"statement":       "A domain validation option is using a method not in the approved list. Email-based validation requires manual intervention and prevents automatic certificate renewal.",
	"likelihood_hint": "medium",
	"impact_hint":     "medium",
	"violation_ids":   ["domain_validation_method_not_approved"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-345",
			"title":       "Insufficient Verification of Data Authenticity",
			"url":         "https://cwe.mitre.org/data/definitions/345.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-693",
			"title":       "Protection Mechanism Failure",
			"url":         "https://cwe.mitre.org/data/definitions/693.html"
		}
	],
	"remediation": {
		"title":       "Re-issue the certificate using DNS validation",
		"description": "Request a replacement certificate for the affected domains using DNS validation so that ACM can renew it automatically without manual intervention.",
		"tasks": [
			{"title": "Request a new ACM certificate for the same domain names specifying DNS validation"},
			{"title": "Add the DNS CNAME records provided by ACM to the domain's DNS zone"},
			{"title": "Wait for ACM to confirm validation and issue the certificate"},
			{"title": "Attach the new certificate to all resources and delete the email-validated certificate"}
		]
	}
}]
