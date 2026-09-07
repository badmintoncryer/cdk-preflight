package cdk_preflight

import rego.v1

_pf_llae_fix := "Use x86_64 and arm64"

_pf_llae_url := "https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.html"

violation contains make_diag_full("pf-lambda-layer-compatible-architectures-enum", "ERROR", name,
	"Properties.CompatibleArchitectures",
	sprintf("architecture '%v'; Lambda runs on x86_64 and arm64", [v]),
	_pf_llae_fix, _pf_llae_url) if {
	some name in _pf_lam_layer
	vs := _pf_lam_list(_pf_lam_get(name, "CompatibleArchitectures"))
	some v in vs
	is_string(v)
	not v in {"x86_64", "arm64"}
}
