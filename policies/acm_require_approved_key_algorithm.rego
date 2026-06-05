# METADATA
# title: ACM certificate must use an approved key algorithm
# description: Weak key algorithms undermine the encryption protecting data in transit. Only algorithms in approved_key_algorithms are permitted.
# custom:
#   controls:
#     - CC6.7
#     - CC7.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_approved_key_algorithm

violation[{"id": "unapproved_key_algorithm"}] if {
	key_alg := object.get(input, "key_algorithm", "")
	not key_alg in data.approved_key_algorithms
}

title := "ACM certificate must use an approved key algorithm"
description := "Weak key algorithms undermine the encryption protecting data in transit. Only algorithms in approved_key_algorithms are permitted."

risk_templates := [{
	"name":            "ACM certificate uses an unapproved key algorithm",
	"title":           "ACM certificate uses a weak or unapproved key algorithm",
	"statement":       "The certificate was issued with a key algorithm that does not meet the required strength standard, weakening the encryption protecting data in transit.",
	"likelihood_hint": "medium",
	"impact_hint":     "high",
	"violation_ids":   ["unapproved_key_algorithm"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-326",
			"title":       "Inadequate Encryption Strength",
			"url":         "https://cwe.mitre.org/data/definitions/326.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-327",
			"title":       "Use of a Broken or Risky Cryptographic Algorithm",
			"url":         "https://cwe.mitre.org/data/definitions/327.html"
		}
	],
	"remediation": {
		"title":       "Re-request the certificate using an approved key algorithm",
		"description": "ACM certificates cannot have their key algorithm changed in place. Request a new certificate with an approved algorithm and migrate all attached resources before deleting the non-compliant certificate.",
		"tasks": [
			{"title": "Request a new ACM certificate specifying an algorithm from the approved_key_algorithms list"},
			{"title": "Attach the new certificate to all resources currently using the non-compliant certificate"},
			{"title": "Validate that the new certificate is in use and services are functioning correctly"},
			{"title": "Delete the non-compliant certificate once all references have been migrated"}
		]
	}
}]
