package cdk_preflight

import rego.v1

_pf_lrmr_fix := "Add RuntimeVersionArn, or use Auto / FunctionUpdate"

_pf_lrmr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-runtimemanagementconfig.html"

violation contains make_diag_full("pf-lambda-runtime-manual-requires-arn", "ERROR", name,
	"Properties.RuntimeManagementConfig.RuntimeVersionArn",
	"UpdateRuntimeOn: Manual without RuntimeVersionArn; Manual mode is the choice to pin one runtime version and needs to be told which",
	_pf_lrmr_fix, _pf_lrmr_url) if {
	some name in _pf_lam_fn
	rmc := _pf_lam_obj(_pf_lam_props(name), "RuntimeManagementConfig")
	object.get(rmc, "UpdateRuntimeOn", "") == "Manual"
	not _pf_lam_has_key(rmc, "RuntimeVersionArn")
}
