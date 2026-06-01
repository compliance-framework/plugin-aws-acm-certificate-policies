package compliance_framework.acm_require_tags

test_no_violation_all_required_tags_present if {
	count(violation) == 0 with input as {
		"tags": {"Environment": "prod", "Owner": "platform-team"}
	}
		with data.required_certificate_tags as ["Environment", "Owner"]
}

test_violation_missing_one_tag if {
	count(violation) == 1 with input as {
		"tags": {"Environment": "prod"}
	}
		with data.required_certificate_tags as ["Environment", "Owner"]
}

test_violation_missing_all_tags if {
	count(violation) == 2 with input as {"tags": {}}
		with data.required_certificate_tags as ["Environment", "Owner"]
}

test_no_violation_no_required_tags if {
	count(violation) == 0 with input as {"tags": {}}
		with data.required_certificate_tags as []
}
