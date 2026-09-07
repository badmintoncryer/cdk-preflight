package cdk_preflight

import rego.v1

_pf_lrle_fix := "Use Allow or Terminate for RecursiveLoop"

_pf_lrle_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"

violation contains make_diag_full("pf-lambda-recursive-loop-enum", "ERROR", name,
	"Properties.RecursiveLoop",
	sprintf("RecursiveLoop '%v'; the recursive-invocation detector is either Allow or Terminate", [v]),
	_pf_lrle_fix, _pf_lrle_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	v := _pf_lam_str(props, "RecursiveLoop")
	_pf_lam_lit(v)
	not v in {"Allow", "Terminate"}
}
