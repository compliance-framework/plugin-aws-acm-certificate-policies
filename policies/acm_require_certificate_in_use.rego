# METADATA
# title: ACM certificate must be attached to an AWS resource
# description: Issued certificates that are not in use indicate orphaned lifecycle objects and potential certificate sprawl.
# custom:
#   controls:
#     - CC6.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_certificate_in_use

violation[{}] if {
	input.status == "ISSUED"
	count(input.in_use_by) == 0
}

title := "ACM certificate must be attached to an AWS resource"
description := "Issued certificates that are not in use indicate orphaned lifecycle objects and potential certificate sprawl."
