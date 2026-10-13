package compliance_framework.acm_require_valid_status

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

test_no_violation_issued_status if {
	count(violation) == 0 with input as {"status": "ISSUED"}
		with data.approved_certificate_statuses as ["ISSUED"] # regal ignore:unresolved-reference
}

test_violation_expired_status if {
	count(violation) == 1 with input as {"status": "EXPIRED"}
		with data.approved_certificate_statuses as ["ISSUED"] # regal ignore:unresolved-reference
}

test_violation_revoked_status if {
	count(violation) == 1 with input as {"status": "REVOKED"}
		with data.approved_certificate_statuses as ["ISSUED"] # regal ignore:unresolved-reference
}

test_violation_failed_status if {
	count(violation) == 1 with input as {"status": "FAILED"}
		with data.approved_certificate_statuses as ["ISSUED"] # regal ignore:unresolved-reference
}

test_violation_id_certificate_status_not_approved if {
	violation[{"id": "certificate_status_not_approved"}] with input as {"status": "EXPIRED"}
		with data.approved_certificate_statuses as ["ISSUED"] # regal ignore:unresolved-reference
}
