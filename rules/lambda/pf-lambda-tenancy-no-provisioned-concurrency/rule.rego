package cdk_preflight

import rego.v1

_pf_ltnp_fix := "Drop ProvisionedConcurrencyConfig, or drop TenancyConfig"

_pf_ltnp_url := "https://docs.aws.amazon.com/lambda/latest/dg/tenant-isolation.html"

violation contains make_diag_full("pf-lambda-tenancy-no-provisioned-concurrency", "ERROR", id,
	"Properties.ProvisionedConcurrencyConfig",
	"provisioned concurrency on a tenant-isolated function; execution environments are created per tenant and cannot be pre-initialised",
	_pf_ltnp_fix, _pf_ltnp_url) if {
	some fname in _pf_lam_fn
	_pf_lam_has(fname, "TenancyConfig")
	some [id, fnref, _] in _pf_lam_pc
	_pf_lam_ref(fnref) == fname
}
