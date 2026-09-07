package cdk_preflight

import rego.v1

_pf_lsmz_fix := "Set MaxExecutionEnvironments to 0 as well, or raise the minimum to 1"

_pf_lsmz_url := "https://docs.aws.amazon.com/lambda/latest/dg/lambda-managed-instances-scaling.html"

violation contains make_diag_full("pf-lambda-scaling-min-zero-requires-max-zero", "ERROR", name,
	"Properties.FunctionScalingConfig.MinExecutionEnvironments",
	sprintf("MinExecutionEnvironments 0 with MaxExecutionEnvironments %v; zero is the way to turn managed scaling off and is only accepted when both bounds are zero", [mx]),
	_pf_lsmz_fix, _pf_lsmz_url) if {
	some name in _pf_lam_fn
	sc := _pf_lam_obj(_pf_lam_props(name), "FunctionScalingConfig")
	object.get(sc, "MinExecutionEnvironments", -1) == 0
	mx := object.get(sc, "MaxExecutionEnvironments", 0)
	mx != 0
}
