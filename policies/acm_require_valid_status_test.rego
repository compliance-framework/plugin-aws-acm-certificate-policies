package compliance_framework.acm_require_valid_status

test_no_violation_issued_status if {
	count(violation) == 0 with input as {"status": "ISSUED"}
		with data.approved_certificate_statuses as ["ISSUED"]
}

test_violation_expired_status if {
	count(violation) == 1 with input as {"status": "EXPIRED"}
		with data.approved_certificate_statuses as ["ISSUED"]
}

test_violation_revoked_status if {
	count(violation) == 1 with input as {"status": "REVOKED"}
		with data.approved_certificate_statuses as ["ISSUED"]
}

test_violation_failed_status if {
	count(violation) == 1 with input as {"status": "FAILED"}
		with data.approved_certificate_statuses as ["ISSUED"]
}
