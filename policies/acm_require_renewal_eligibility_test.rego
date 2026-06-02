package compliance_framework.acm_require_renewal_eligibility

import rego.v1

# Pinned "now": 2024-01-01T00:00:00Z = 1704067200000000000 ns
# 90-day deadline:  2024-03-31T00:00:00Z = 1711843200000000000 ns
# Just inside  (89 days): 2024-03-30T00:00:00Z = 1711756800000000000 ns
# Just outside (91 days): 2024-04-01T00:00:00Z = 1711929600000000000 ns
# Already expired:         2023-12-01T00:00:00Z = 1701388800000000000 ns

# AMAZON_ISSUED, ELIGIBLE, just inside 90-day window — no violation
test_no_violation_eligible_near_expiry if {
	count(violation) == 0 with input as {
		"type": "AMAZON_ISSUED",
		"status": "ISSUED",
		"renewal_eligibility": "ELIGIBLE",
		"not_after": "2024-03-30T00:00:00Z",
	}
		with data.renewal_warning_days as 90
		with time.now_ns as 1704067200000000000
}

# AMAZON_ISSUED, INELIGIBLE, just inside 90-day window — violation
test_violation_ineligible_near_expiry if {
	count(violation) == 1 with input as {
		"type": "AMAZON_ISSUED",
		"status": "ISSUED",
		"renewal_eligibility": "INELIGIBLE",
		"not_after": "2024-03-30T00:00:00Z",
	}
		with data.renewal_warning_days as 90
		with time.now_ns as 1704067200000000000
}

# AMAZON_ISSUED, INELIGIBLE, just outside 90-day window — no violation
test_no_violation_ineligible_not_near_expiry if {
	count(violation) == 0 with input as {
		"type": "AMAZON_ISSUED",
		"status": "ISSUED",
		"renewal_eligibility": "INELIGIBLE",
		"not_after": "2024-04-01T00:00:00Z",
	}
		with data.renewal_warning_days as 90
		with time.now_ns as 1704067200000000000
}

# IMPORTED cert — exempt even when inside the window
test_no_violation_imported_cert if {
	count(violation) == 0 with input as {
		"type": "IMPORTED",
		"status": "ISSUED",
		"renewal_eligibility": "",
		"not_after": "2024-03-30T00:00:00Z",
	}
		with data.renewal_warning_days as 90
		with time.now_ns as 1704067200000000000
}

# AMAZON_ISSUED, INELIGIBLE, already expired — no violation (lower bound excludes past certs)
test_no_violation_ineligible_already_expired if {
	count(violation) == 0 with input as {
		"type": "AMAZON_ISSUED",
		"status": "ISSUED",
		"renewal_eligibility": "INELIGIBLE",
		"not_after": "2023-12-01T00:00:00Z",
	}
		with data.renewal_warning_days as 90
		with time.now_ns as 1704067200000000000
}
