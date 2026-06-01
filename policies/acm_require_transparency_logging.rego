# METADATA
# title: ACM certificate must have transparency logging enabled
# description: Certificate transparency logging is required for ACM-issued certificates. Disabling it prevents detection of mis-issued certificates.
# custom:
#   controls:
#     - CC6.7
#     - CC7.1
#   schedule: "0 */6 * * *"

package compliance_framework.acm_require_transparency_logging

violation[{}] if {
	input.transparency_logging_preference == "DISABLED"
}

title := "ACM certificate must have transparency logging enabled"
description := "Certificate transparency logging is required for ACM-issued certificates. Disabling it prevents detection of mis-issued certificates."
