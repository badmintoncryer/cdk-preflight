package cdk_preflight

import rego.v1

_pf_luie_fix := "Set InvokeMode to BUFFERED or RESPONSE_STREAM"

_pf_luie_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-url.html"

violation contains make_diag_full("pf-lambda-url-invoke-mode-enum", "ERROR", name,
	"Properties.InvokeMode",
	sprintf("InvokeMode '%v'; the URL either buffers the response (BUFFERED) or streams it (RESPONSE_STREAM)", [v]),
	_pf_luie_fix, _pf_luie_url) if {
	some name in _pf_lam_url
	v := resolve(name, "Properties.InvokeMode")
	is_string(v)
	not v in {"BUFFERED", "RESPONSE_STREAM"}
}
