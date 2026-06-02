package compliance_framework.acm_require_renewal_eligibility

import future.keywords.if

# AMAZON_ISSUED, ELIGIBLE, near expiry — no violation
test_no_violation_eligible_near_expiry if {
	count(violation) == 0 with input as {
		"type": "AMAZON_ISSUED",
		"status": "ISSUED",
		"renewal_eligibility": "ELIGIBLE",
		"not_after": "2000-01-01T00:00:00Z",
	}
		with data.renewal_warning_days as 90
}

# AMAZON_ISSUED, INELIGIBLE, near expiry — violation
test_violation_ineligible_near_expiry if {
	count(violation) == 1 with input as {
		"type": "AMAZON_ISSUED",
		"status": "ISSUED",
		"renewal_eligibility": "INELIGIBLE",
		"not_after": "2000-01-01T00:00:00Z",
	}
		with data.renewal_warning_days as 90
}

# IMPORTED cert — exempt regardless of expiry
test_no_violation_imported_cert if {
	count(violation) == 0 with input as {
		"type": "IMPORTED",
		"status": "ISSUED",
		"renewal_eligibility": "",
		"not_after": "2000-01-01T00:00:00Z",
	}
		with data.renewal_warning_days as 90
}

# AMAZON_ISSUED, INELIGIBLE, but far-future expiry — no violation
test_no_violation_ineligible_not_near_expiry if {
	count(violation) == 0 with input as {
		"type": "AMAZON_ISSUED",
		"status": "ISSUED",
		"renewal_eligibility": "INELIGIBLE",
		"not_after": "2099-01-01T00:00:00Z",
	}
		with data.renewal_warning_days as 90
}
