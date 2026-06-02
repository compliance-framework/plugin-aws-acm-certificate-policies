package compliance_framework.acm_require_no_expired_cert_in_use

# EXPIRED cert with in_use_by — one violation per attached resource
test_violation_expired_in_use if {
	count(violation) == 1 with input as {
		"status": "EXPIRED",
		"in_use_by": ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/foo/bar"],
	}
		with data.approved_certificate_statuses as ["ISSUED"]
}

# EXPIRED cert, empty in_use_by — no violation
test_no_violation_expired_not_in_use if {
	count(violation) == 0 with input as {
		"status": "EXPIRED",
		"in_use_by": [],
	}
		with data.approved_certificate_statuses as ["ISSUED"]
}

# ISSUED cert with in_use_by — no violation
test_no_violation_issued_in_use if {
	count(violation) == 0 with input as {
		"status": "ISSUED",
		"in_use_by": ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/foo/bar"],
	}
		with data.approved_certificate_statuses as ["ISSUED"]
}

# REVOKED cert with multiple resources — one violation per resource
test_violation_revoked_multiple_resources if {
	count(violation) == 2 with input as {
		"status": "REVOKED",
		"in_use_by": [
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/foo/bar",
			"arn:aws:cloudfront::123456789012:distribution/EDFDVBD6EXAMPLE",
		],
	}
		with data.approved_certificate_statuses as ["ISSUED"]
}
