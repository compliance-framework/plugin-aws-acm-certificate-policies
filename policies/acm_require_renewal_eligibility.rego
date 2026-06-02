# METADATA
# title: ACM-issued certificate must be eligible for automatic renewal when nearing expiry
# description: Certificates with renewal_eligibility=INELIGIBLE require manual action to renew.
#              Flag them early to avoid lapses in the access-removal and re-issuance process.
# custom:
#   controls:
#     - CC6.2
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_renewal_eligibility

violation[{}] if {
	input.type == "AMAZON_ISSUED"
	input.status == "ISSUED"
	input.renewal_eligibility != "ELIGIBLE"
	warning_days := data.renewal_warning_days
	now_ns := time.now_ns()
	deadline_ns := now_ns + (warning_days * 24 * 60 * 60 * 1000000000)
	expiry_ns := time.parse_rfc3339_ns(input.not_after)
	expiry_ns >= now_ns
	expiry_ns <= deadline_ns
}

title := "ACM-issued certificate must be eligible for automatic renewal when nearing expiry"
description := "Certificates with renewal_eligibility=INELIGIBLE require manual action to renew. Flag them early to avoid lapses in the access-removal and re-issuance process."
