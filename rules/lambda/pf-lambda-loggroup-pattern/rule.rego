package cdk_preflight

import rego.v1

_pf_llgp_fix := "Use only letters, digits and . - _ / # in the log group name (1-512 characters)"

_pf_llgp_url := "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-loggroups.html"

violation contains make_diag_full("pf-lambda-loggroup-pattern", "ERROR", name,
	"Properties.LoggingConfig.LogGroup",
	sprintf("log group '%v'; CloudWatch Logs accepts 1-512 characters from [.-_/#A-Za-z0-9] only", [lg]),
	_pf_llgp_fix, _pf_llgp_url) if {
	some name in _pf_lam_fn
	lc := _pf_lam_obj(_pf_lam_props(name), "LoggingConfig")
	lg := _pf_lam_str(lc, "LogGroup")
	_pf_lam_lit(lg)
	not regex.match(`^[\.\-_/#A-Za-z0-9]{1,512}$`, lg)
}
