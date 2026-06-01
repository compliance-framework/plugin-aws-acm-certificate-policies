# METADATA
# title: ACM certificate must carry all required tags
# description: Missing required tags prevent cost attribution, ownership tracing, and lifecycle management of certificates.
# custom:
#   controls:
#     - CC6.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_tags

violation[{"missing_tag": tag}] if {
	some tag in data.required_certificate_tags
	not input.tags[tag]
}

title := "ACM certificate must carry all required tags"
description := "Missing required tags prevent cost attribution, ownership tracing, and lifecycle management of certificates."
