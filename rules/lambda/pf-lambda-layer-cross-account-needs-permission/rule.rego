package cdk_preflight

import rego.v1

_pf_llcp_fix := "Add a LayerVersionPermission on the owning account, or copy the layer"

_pf_llcp_url := "https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html"

violation contains make_diag_full("pf-lambda-layer-cross-account-needs-permission", "ERROR", name,
	"Properties.Layers",
	sprintf("layer '%v' is owned by another account with no LayerVersionPermission in the template; the owner has to grant lambda:GetLayerVersion before the function can attach it", [arn]),
	_pf_llcp_fix, _pf_llcp_url) if {
	some name in _pf_lam_fn
	some arn in _pf_lam_list(_pf_lam_get(name, "Layers"))
	parts := _pf_lam_arn(arn)
	parts[2] == "lambda"
	parts[4] != "${AWS::AccountId}"
	count(resources_of_type("AWS::Lambda::LayerVersionPermission")) == 0
}
