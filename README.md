# plugin-aws-acm-certificate-policies

OPA policy bundle for the CCF `plugin-aws-acm` plugin.

## Policies

| Policy | Check |
|--------|-------|
| `acm_certificate_approved` | Certificate must carry an `approval=true` tag |

## Prerequisites

- [OPA](https://www.openpolicyagent.org/docs/latest/#1-download-opa)

## Usage

```sh
make test      # run policy tests
make validate  # static check
make build     # produce dist/bundle.tar.gz
```
