# METADATA
# title: Non-ISSUED certificate must not be attached to any AWS resource
# description: An expired or revoked certificate still appearing in in_use_by indicates
#              that the access-removal trigger failed to propagate to the endpoint.
# custom:
#   controls:
#     - CC6.2
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_no_expired_cert_in_use

violation[{"resource": resource}] if {
	not input.status in data.approved_certificate_statuses
	resource := input.in_use_by[_]
}

title := "Non-ISSUED certificate must not be attached to any AWS resource"
description := "An expired or revoked certificate still appearing in in_use_by indicates that the access-removal trigger failed to propagate to the endpoint."
