package cdk_preflight

import rego.v1

_pf_lcszo_fix := "Drop CodeSigningConfigArn from container image functions"

_pf_lcszo_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html"

violation contains make_diag_full("pf-lambda-code-signing-zip-only", "ERROR", name,
	"Properties.CodeSigningConfigArn",
	"a code signing config on a container image function; Lambda verifies signatures on .zip archives only and the function create is rejected",
	_pf_lcszo_fix, _pf_lcszo_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	_pf_lam_has_key(props, "CodeSigningConfigArn")
	object.get(props, "PackageType", "Zip") == "Image"
}
