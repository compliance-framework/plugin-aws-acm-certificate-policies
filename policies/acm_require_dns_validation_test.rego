package compliance_framework.acm_require_dns_validation

test_no_violation_dns_validation if {
	count(violation) == 0 with input as {
		"domain_validation_options": [
			{"domain_name": "example.com", "validation_method": "DNS"},
		]
	}
		with data.approved_validation_methods as ["DNS"]
}

test_violation_email_validation if {
	count(violation) == 1 with input as {
		"domain_validation_options": [
			{"domain_name": "example.com", "validation_method": "EMAIL"},
		]
	}
		with data.approved_validation_methods as ["DNS"]
	violation[{"id": "domain_validation_method_not_approved", "domain_name": "example.com"}] with input as {
		"domain_validation_options": [
			{"domain_name": "example.com", "validation_method": "EMAIL"},
		]
	}
		with data.approved_validation_methods as ["DNS"]
}

test_violation_mixed_methods if {
	count(violation) == 1 with input as {
		"domain_validation_options": [
			{"domain_name": "example.com", "validation_method": "DNS"},
			{"domain_name": "www.example.com", "validation_method": "EMAIL"},
		]
	}
		with data.approved_validation_methods as ["DNS"]
}

test_violation_two_failing_domains if {
	count(violation) == 2 with input as {
		"domain_validation_options": [
			{"domain_name": "example.com", "validation_method": "EMAIL"},
			{"domain_name": "www.example.com", "validation_method": "EMAIL"},
		]
	}
		with data.approved_validation_methods as ["DNS"]
}

test_no_violation_no_domains if {
	count(violation) == 0 with input as {"domain_validation_options": []}
		with data.approved_validation_methods as ["DNS"]
}
