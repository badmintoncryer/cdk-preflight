package cdk_preflight

import rego.v1

_pf_llgap_fix := "Name the log group without the reserved aws/ prefix"

_pf_llgap_url := "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-loggroups.html"

violation contains make_diag_full("pf-lambda-loggroup-no-aws-prefix", "ERROR", name,
	"Properties.LoggingConfig.LogGroup",
	sprintf("log group '%v'; the aws/ prefix is reserved for AWS-managed log groups and CreateFunction rejects it", [lg]),
	_pf_llgap_fix, _pf_llgap_url) if {
	some name in _pf_lam_fn
	lc := _pf_lam_obj(_pf_lam_props(name), "LoggingConfig")
	lg := _pf_lam_str(lc, "LogGroup")
	_pf_lam_lit(lg)
	startswith(lg, "aws/")
}
