# plugin-aws-acm-certificate-policies

OPA policy bundle for the CCF [`plugin-aws-acm`](https://github.com/container-solutions/plugin-aws-acm) plugin. Evaluates AWS Certificate Manager certificates for SOC2 compliance.

## Policies

| Policy | Check | SOC2 Controls |
|--------|-------|---------------|
| `acm_certificate_approved` | Certificate must carry an `approval=true` tag | CC6.1 |
| `acm_require_certificate_not_expiring` | Certificate must not expire within `expiry_warning_days` days | CC7.2, CC9.1 |
| `acm_require_valid_status` | Certificate status must be in `approved_certificate_statuses` | CC6.1, CC6.7 |
| `acm_require_approved_key_algorithm` | Key algorithm must be in `approved_key_algorithms` | CC6.7, CC7.1 |
| `acm_require_transparency_logging` | Certificate transparency logging must be `ENABLED` | CC6.7, CC7.1 |
| `acm_require_dns_validation` | All domain validation methods must be in `approved_validation_methods` | CC9.1, A1.2 |
| `acm_require_certificate_in_use` | Issued certificates must be attached to at least one AWS resource | CC6.1 |
| `acm_require_tags` | Certificate must carry all keys listed in `required_certificate_tags` | CC6.1 |

## Prerequisites

- [OPA](https://www.openpolicyagent.org/docs/latest/#1-download-opa) >= 1.6.0

## Usage

```sh
make test      # run policy tests
make validate  # static check (opa check)
make build     # produce dist/bundle.tar.gz
```

## data.json reference

All configurable thresholds and allowed values are set in `policies/data.json`. Override individual keys in the agent config via `policy_data`.

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `expiry_warning_days` | integer | `30` | Certs expiring within this many days trigger a violation on `acm_require_certificate_not_expiring` |
| `approved_certificate_statuses` | string array | `["ISSUED"]` | Statuses not in this list trigger a violation on `acm_require_valid_status` |
| `approved_key_algorithms` | string array | `["RSA_2048","RSA_4096","EC_prime256v1","EC_secp384r1"]` | Algorithms not in this list trigger a violation on `acm_require_approved_key_algorithm`. Values match the ACM API `KeyAlgorithm` enum exactly |
| `approved_validation_methods` | string array | `["DNS"]` | Validation methods not in this list trigger a violation on `acm_require_dns_validation` |
| `required_certificate_tags` | string array | `["Environment","Owner"]` | Missing tag keys trigger a violation on `acm_require_tags` |

## Writing new policies

1. Create `policies/acm_<check_name>.rego` following this structure:

```rego
# METADATA
# title: <one-line title>
# description: <what this checks and why it matters>
# custom:
#   controls:
#     - <SOC2-control-id>

package compliance_framework.acm_<check_name>

violation[{}] if {
    # rule body using input.<field> and data.<parameter>
}

title := "<one-line title>"
description := "<what this checks and why it matters>"
```

2. Add configurable thresholds to `policies/data.json` — never hardcode values in policy files.

3. Create `policies/acm_<check_name>_test.rego` with at minimum: one passing case, one failing case, and one edge case (e.g. missing field).

4. Run `make test` and `make validate` to confirm all tests pass and the bundle compiles.
