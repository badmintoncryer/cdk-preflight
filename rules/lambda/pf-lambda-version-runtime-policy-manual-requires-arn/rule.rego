package cdk_preflight

import rego.v1

_pf_lvrp_fix := "Add RuntimePolicy.RuntimeVersionArn, or use Auto"

_pf_lvrp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-version-runtimepolicy.html"

violation contains make_diag_full("pf-lambda-version-runtime-policy-manual-requires-arn", "ERROR", name,
	"Properties.RuntimePolicy.RuntimeVersionArn",
	"RuntimePolicy.UpdateRuntimeOn: Manual without RuntimeVersionArn; the version has no runtime to pin to",
	_pf_lvrp_fix, _pf_lvrp_url) if {
	some name in _pf_lam_ver
	rp := _pf_lam_obj(_pf_lam_props(name), "RuntimePolicy")
	object.get(rp, "UpdateRuntimeOn", "") == "Manual"
	not _pf_lam_has_key(rp, "RuntimeVersionArn")
}
