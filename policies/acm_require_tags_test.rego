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

test_violation_missing_approval_tag if {
	count(violation) == 1 with input as {
		"tags": {"Environment": "prod", "Owner": "platform-team"}
	}
		with data.required_certificate_tags as ["approval", "Environment", "Owner"]
}

test_no_violation_approval_tag_present if {
	count(violation) == 0 with input as {
		"tags": {"approval": "true", "Environment": "prod", "Owner": "platform-team"}
	}
		with data.required_certificate_tags as ["approval", "Environment", "Owner"]
		with data.required_tag_values as {"approval": "true"}
}

test_violation_approval_tag_wrong_value if {
	count(violation) == 1 with input as {
		"tags": {"approval": "false", "Environment": "prod", "Owner": "platform-team"}
	}
		with data.required_certificate_tags as ["approval", "Environment", "Owner"]
		with data.required_tag_values as {"approval": "true"}
}

test_violation_id_certificate_tags_missing if {
	violation[{"id": "certificate_tags_missing_or_incorrect", "missing_tag": "Environment"}]
		with input as {"tags": {}}
		with data.required_certificate_tags as ["Environment"]
		with data.required_tag_values as {}
}

test_violation_id_certificate_tags_invalid_value if {
	violation[{"id": "certificate_tags_missing_or_incorrect", "invalid_tag_value": "env", "expected": "prod", "got": "dev"}]
		with input as {"tags": {"env": "dev"}}
		with data.required_certificate_tags as []
		with data.required_tag_values as {"env": "prod"}
}
