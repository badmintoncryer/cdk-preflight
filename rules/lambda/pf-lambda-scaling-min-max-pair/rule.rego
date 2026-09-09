package cdk_preflight

import rego.v1

_pf_lsmp_fix := "Set MinExecutionEnvironments and MaxExecutionEnvironments together"

_pf_lsmp_url := "https://docs.aws.amazon.com/lambda/latest/dg/lambda-managed-instances-scaling.html"

violation contains make_diag_full("pf-lambda-scaling-min-max-pair", "WARN", name,
	"Properties.FunctionScalingConfig",
	sprintf("FunctionScalingConfig with %v alone; the scaling bounds are set as a pair", [key]),
	_pf_lsmp_fix, _pf_lsmp_url) if {
	some name in _pf_lam_fn
	sc := _pf_lam_obj(_pf_lam_props(name), "FunctionScalingConfig")
	pair := {"MinExecutionEnvironments": "MaxExecutionEnvironments", "MaxExecutionEnvironments": "MinExecutionEnvironments"}
	some key, other in pair
	_pf_lam_has_key(sc, key)
	not _pf_lam_has_key(sc, other)
}
