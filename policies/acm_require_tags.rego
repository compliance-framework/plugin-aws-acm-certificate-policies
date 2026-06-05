# METADATA
# title: ACM certificate must carry all required tags
# description: Missing required tags prevent cost attribution, ownership tracing, and lifecycle management of certificates.
# custom:
#   controls:
#     - CC6.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_tags

violation[{"id": "certificate_tags_missing_or_incorrect", "missing_tag": tag}] if {
	some tag in data.required_certificate_tags
	not input.tags[tag]
}

violation[{"id": "certificate_tags_missing_or_incorrect", "invalid_tag_value": tag, "expected": expected, "got": got}] if {
	some tag, expected in data.required_tag_values
	got := input.tags[tag]
	got != expected
}

title := "ACM certificate must carry all required tags"
description := "Missing required tags prevent cost attribution, ownership tracing, and lifecycle management of certificates."

risk_templates := [{
	"name":            "ACM certificate required tags are missing or incorrect",
	"title":           "ACM certificate has missing or incorrect required tags",
	"statement":       "One or more required tags are absent or carry an incorrect value, preventing cost attribution, ownership tracing, and lifecycle management of the certificate.",
	"likelihood_hint": "low",
	"impact_hint":     "low",
	"violation_ids":   ["certificate_tags_missing_or_incorrect"],
	"threat_refs": [
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title":       "Improper Access Control",
			"url":         "https://cwe.mitre.org/data/definitions/284.html"
		},
		{
			"system":      "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title":       "Incomplete Documentation",
			"url":         "https://cwe.mitre.org/data/definitions/1059.html"
		}
	],
	"remediation": {
		"title":       "Apply all required tags with correct values to the ACM certificate",
		"description": "Add the missing tags and correct any tag values that do not match policy requirements so the certificate can be attributed to the correct owner, cost centre, and environment.",
		"tasks": [
			{"title": "Review the required tag keys in data.required_certificate_tags and expected values in data.required_tag_values"},
			{"title": "Add the missing tags to the certificate via the AWS Console, CLI, or infrastructure-as-code"},
			{"title": "Correct any existing tag values that do not match the required values"},
			{"title": "Enforce tagging at certificate request time using AWS Tag Policies or IaC pre-deployment checks to prevent recurrence"}
		]
	}
}]
