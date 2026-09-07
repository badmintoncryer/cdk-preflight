package cdk_preflight

import rego.v1

_pf_lcpj_fix := "Set LoggingConfig.LogFormat to JSON"

_pf_lcpj_url := "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-logformat.html"

violation contains make_diag_full("pf-lambda-capacity-provider-json-log-only", "ERROR", name,
	"Properties.LoggingConfig.LogFormat",
	"LogFormat: Text on a function backed by a capacity provider; Lambda Managed Instances emit structured logs only",
	_pf_lcpj_fix, _pf_lcpj_url) if {
	some name in _pf_lam_fn
	cpc := _pf_lam_obj(_pf_lam_props(name), "CapacityProviderConfig")
	lmi := _pf_lam_obj(cpc, "LambdaManagedInstancesCapacityProviderConfig")
	lmi == lmi
	object.get(_pf_lam_obj(_pf_lam_props(name), "LoggingConfig"), "LogFormat", "JSON") == "Text"
}
