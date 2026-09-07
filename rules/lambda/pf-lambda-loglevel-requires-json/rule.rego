package cdk_preflight

import rego.v1

_pf_llrj_fix := "Set LogFormat: JSON, or drop ApplicationLogLevel / SystemLogLevel"

_pf_llrj_url := "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-log-level.html"

violation contains make_diag_full("pf-lambda-loglevel-requires-json", "ERROR", name,
	sprintf("Properties.LoggingConfig.%v", [key]),
	sprintf("%v with LogFormat '%v'; log-level filtering is only applied to JSON-formatted logs and the create is rejected", [key, fmt]),
	_pf_llrj_fix, _pf_llrj_url) if {
	some name in _pf_lam_fn
	lc := _pf_lam_obj(_pf_lam_props(name), "LoggingConfig")
	some key in ["ApplicationLogLevel", "SystemLogLevel"]
	_pf_lam_has_key(lc, key)
	fmt := object.get(lc, "LogFormat", "Text")
	fmt != "JSON"
}
