# METADATA
# title: ACM certificate must use an approved key algorithm
# description: Weak key algorithms undermine the encryption protecting data in transit. Only algorithms in approved_key_algorithms are permitted.
# custom:
#   controls:
#     - CC6.7
#     - CC7.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_approved_key_algorithm

violation[{}] if {
	not input.key_algorithm in data.approved_key_algorithms
}

title := "ACM certificate must use an approved key algorithm"
description := "Weak key algorithms undermine the encryption protecting data in transit. Only algorithms in approved_key_algorithms are permitted."
