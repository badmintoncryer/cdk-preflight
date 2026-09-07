package cdk_preflight

import rego.v1

_pf_ltme_fix := "Use Active or PassThrough for TracingConfig.Mode"

_pf_ltme_url := "https://docs.aws.amazon.com/lambda/latest/api/API_TracingConfig.html"

violation contains make_diag_full("pf-lambda-tracing-mode-enum", "ERROR", name,
	"Properties.TracingConfig.Mode",
	sprintf("TracingConfig.Mode '%v'; X-Ray tracing is either Active or PassThrough", [v]),
	_pf_ltme_fix, _pf_ltme_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	v := _pf_lam_str(_pf_lam_obj(props, "TracingConfig"), "Mode")
	_pf_lam_lit(v)
	not v in {"Active", "PassThrough"}
}
