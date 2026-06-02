# METADATA
# title: ACM certificate must have an approved status
# description: Certificates must have a status listed in approved_certificate_statuses. Any status not explicitly approved, including PENDING_VALIDATION and INACTIVE, is a violation.
# custom:
#   controls:
#     - CC6.1
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_valid_status

violation[{}] if {
	not input.status in data.approved_certificate_statuses
}

title := "ACM certificate must have an approved status"
description := "Certificates must have a status listed in approved_certificate_statuses. Any status not explicitly approved, including PENDING_VALIDATION and INACTIVE, is a violation."
