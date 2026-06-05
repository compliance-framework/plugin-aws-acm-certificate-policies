# METADATA
# title: ACM certificate must be attached to an AWS resource
# description: Issued certificates that are not in use indicate orphaned lifecycle objects and potential certificate sprawl.
# custom:
#   controls:
#     - CC6.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_certificate_in_use

violation[{"id": "certificate_not_in_use"}] if {
	input.status == "ISSUED"
	in_use_by := object.get(input, "in_use_by", [])
	count(in_use_by) == 0
}

title := "ACM certificate must be attached to an AWS resource"
description := "Issued certificates that are not in use indicate orphaned lifecycle objects and potential certificate sprawl."

risk_templates := [{
	"name":            "ACM certificate is not attached to any AWS resource",
	"title":           "ACM issued certificate is not in use",
	"statement":       "An issued certificate with no attached resources represents certificate sprawl, increases the attack surface, and may indicate a failed or abandoned deployment.",
	"likelihood_hint": "low",
	"impact_hint":     "low",
	"violation_ids":   ["certificate_not_in_use"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title":       "Incomplete Documentation",
			"url":         "https://cwe.mitre.org/data/definitions/1059.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-404",
			"title":       "Improper Resource Shutdown or Release",
			"url":         "https://cwe.mitre.org/data/definitions/404.html"
		}
	],
	"remediation": {
		"title":       "Attach the certificate to a resource or delete it",
		"description": "Determine whether the certificate is required. Attach it to the intended resource, or delete it if it was issued in error or is no longer needed.",
		"tasks": [
			{"title": "Identify the intended use case for the certificate"},
			{"title": "Attach the certificate to the appropriate load balancer, CloudFront distribution, or API Gateway if still required"},
			{"title": "If the certificate is no longer needed, delete it from ACM"},
			{"title": "Review IAM and deployment pipelines to prevent orphaned certificates being issued in future"}
		]
	}
}]
