package compliance_framework.acm_require_certificate_not_expiring

import future.keywords.if

# Far-future expiry — no violation expected
test_no_violation_cert_not_expiring if {
	count(violation) == 0 with input as {"not_after": "2099-01-01T00:00:00Z"}
		with data.expiry_warning_days as 30
}

# Expiry within warning window — violation expected
test_violation_cert_expiring_soon if {
	count(violation) == 1 with input as {"not_after": "2000-01-01T00:00:00Z"}
		with data.expiry_warning_days as 30
}

# No not_after field — rule body undefined, no violation
test_no_violation_no_expiry_field if {
	count(violation) == 0 with input as {}
		with data.expiry_warning_days as 30
}
