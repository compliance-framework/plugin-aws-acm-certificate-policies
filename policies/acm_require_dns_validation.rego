# METADATA
# title: ACM certificate must use an approved domain validation method
# description: Email-based validation requires manual intervention and creates availability risk. DNS validation enables automatic renewal.
# custom:
#   controls:
#     - CC9.1
#     - A1.2
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_dns_validation

violation[{"domain_name": dvo.domain_name}] if {
	some dvo in input.domain_validation_options
	not dvo.validation_method in data.approved_validation_methods
}

title := "ACM certificate must use an approved domain validation method"
description := "Email-based validation requires manual intervention and creates availability risk. DNS validation enables automatic renewal."
