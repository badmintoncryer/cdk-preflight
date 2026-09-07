package cdk_preflight

import rego.v1

_pf_lrmo_fix := "Set UpdateRuntimeOn: Manual, or drop RuntimeVersionArn"

_pf_lrmo_url := "https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html"

violation contains make_diag_full("pf-lambda-runtime-arn-manual-only", "ERROR", name,
	"Properties.RuntimeManagementConfig.RuntimeVersionArn",
	sprintf("RuntimeVersionArn with UpdateRuntimeOn '%v'; a runtime version can only be pinned in Manual mode", [mode]),
	_pf_lrmo_fix, _pf_lrmo_url) if {
	some name in _pf_lam_fn
	rmc := _pf_lam_obj(_pf_lam_props(name), "RuntimeManagementConfig")
	_pf_lam_has_key(rmc, "RuntimeVersionArn")
	mode := object.get(rmc, "UpdateRuntimeOn", "Auto")
	mode != "Manual"
}
