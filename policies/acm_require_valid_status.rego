# METADATA
# title: ACM certificate must have an approved status
# description: Certificates with status EXPIRED, REVOKED, FAILED, or VALIDATION_TIMED_OUT are not providing effective protection.
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
description := "Certificates with status EXPIRED, REVOKED, FAILED, or VALIDATION_TIMED_OUT are not providing effective protection."
