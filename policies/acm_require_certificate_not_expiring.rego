# METADATA
# title: ACM certificate must not be expiring within the warning window
# description: Certificates expiring within expiry_warning_days days indicate a renewal risk that can cause service outages.
# custom:
#   controls:
#     - CC7.2
#     - CC9.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_certificate_not_expiring

violation[{}] if {
	warning_days := data.expiry_warning_days
	deadline_ns := time.now_ns() + (warning_days * 24 * 60 * 60 * 1000000000)
	expiry_ns := time.parse_rfc3339_ns(input.not_after)
	expiry_ns < deadline_ns
}

title := "ACM certificate must not be expiring within the warning window"
description := "Certificates expiring within expiry_warning_days days indicate a renewal risk that can cause service outages."
