package compliance_framework.acm_certificate_approved

test_violation_missing_approval_tag if {
	count(violation) == 1 with input as {"tags": {}}
}

test_violation_wrong_approval_tag_value if {
	count(violation) == 1 with input as {"tags": {"approval": "false"}}
}

test_no_violation_approval_tag_present if {
	count(violation) == 0 with input as {"tags": {"approval": "true"}}
}
