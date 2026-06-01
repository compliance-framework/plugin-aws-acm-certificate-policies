package compliance_framework.acm_require_certificate_in_use

test_no_violation_cert_in_use if {
	count(violation) == 0 with input as {
		"status": "ISSUED",
		"in_use_by": ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/abc123"],
	}
}

test_violation_issued_cert_not_in_use if {
	count(violation) == 1 with input as {
		"status": "ISSUED",
		"in_use_by": [],
	}
}

test_no_violation_pending_cert_not_in_use if {
	count(violation) == 0 with input as {
		"status": "PENDING_VALIDATION",
		"in_use_by": [],
	}
}
