package compliance_framework.acm_require_approved_key_algorithm

test_no_violation_rsa_2048 if {
	count(violation) == 0 with input as {"key_algorithm": "RSA_2048"}
		with data.approved_key_algorithms as ["RSA_2048", "RSA_4096", "EC_prime256v1", "EC_secp384r1"]
}

test_no_violation_ecdsa if {
	count(violation) == 0 with input as {"key_algorithm": "EC_prime256v1"}
		with data.approved_key_algorithms as ["RSA_2048", "RSA_4096", "EC_prime256v1", "EC_secp384r1"]
}

test_violation_rsa_1024 if {
	count(violation) == 1 with input as {"key_algorithm": "RSA_1024"}
		with data.approved_key_algorithms as ["RSA_2048", "RSA_4096", "EC_prime256v1", "EC_secp384r1"]
}

test_violation_unknown_algorithm if {
	count(violation) == 1 with input as {"key_algorithm": "UNKNOWN"}
		with data.approved_key_algorithms as ["RSA_2048", "RSA_4096", "EC_prime256v1", "EC_secp384r1"]
}

test_violation_missing_key_algorithm if {
	count(violation) == 1 with input as {}
		with data.approved_key_algorithms as ["RSA_2048", "RSA_4096", "EC_prime256v1", "EC_secp384r1"]
}

test_violation_id_unapproved_key_algorithm if {
	violation[{"id": "unapproved_key_algorithm"}] with input as {"key_algorithm": "RSA_1024"}
		with data.approved_key_algorithms as ["RSA_2048"]
}
