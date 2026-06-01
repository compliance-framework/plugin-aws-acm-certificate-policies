package compliance_framework.acm_require_transparency_logging

test_no_violation_logging_enabled if {
	count(violation) == 0 with input as {"transparency_logging_preference": "ENABLED"}
}

test_violation_logging_disabled if {
	count(violation) == 1 with input as {"transparency_logging_preference": "DISABLED"}
}

test_no_violation_empty_preference if {
	count(violation) == 0 with input as {"transparency_logging_preference": ""}
}
