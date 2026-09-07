package cdk_preflight

import rego.v1

_pf_lpcnl_fix := "Point the alias at a published version before adding ProvisionedConcurrencyConfig"

_pf_lpcnl_url := "https://docs.aws.amazon.com/lambda/latest/dg/provisioned-concurrency.html"

violation contains make_diag_full("pf-lambda-provisioned-concurrency-not-latest", "ERROR", name,
	"Properties.ProvisionedConcurrencyConfig",
	"provisioned concurrency on an alias that resolves to $LATEST; only published versions can be pre-initialised",
	_pf_lpcnl_fix, _pf_lpcnl_url) if {
	some name in _pf_lam_alias
	props := _pf_lam_props(name)
	_pf_lam_has_key(props, "ProvisionedConcurrencyConfig")
	object.get(props, "FunctionVersion", "") == "$LATEST"
}
