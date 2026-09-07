package cdk_preflight

import rego.v1

_pf_llsl_fix := "Use DEBUG, INFO or WARN for SystemLogLevel"

_pf_llsl_url := "https://docs.aws.amazon.com/lambda/latest/api/API_LoggingConfig.html"

violation contains make_diag_full("pf-lambda-system-log-level-enum", "ERROR", name,
	"Properties.LoggingConfig.SystemLogLevel",
	sprintf("SystemLogLevel '%v'; the Lambda system logs only carry DEBUG, INFO and WARN", [lvl]),
	_pf_llsl_fix, _pf_llsl_url) if {
	some name in _pf_lam_fn
	lc := _pf_lam_obj(_pf_lam_props(name), "LoggingConfig")
	lvl := _pf_lam_str(lc, "SystemLogLevel")
	_pf_lam_lit(lvl)
	not lvl in {"DEBUG", "INFO", "WARN"}
}
