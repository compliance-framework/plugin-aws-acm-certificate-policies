package compliance_framework.acm_certificate_approved

violation[{}] if {
	not input.tags["approval"] == "true"
}

title := "ACM certificate must carry approval=true tag"
description := "All ACM certificates must be tagged approval=true to confirm they have been reviewed."
