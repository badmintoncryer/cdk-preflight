package cdk_preflight

import rego.v1

_pf_llar_fix := "Reference a layer version in the same region as the function"

_pf_llar_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html"

violation contains make_diag_full("pf-lambda-layer-arn-region", "ERROR", name,
	"Properties.Layers",
	sprintf("layer region '%v' is not the deploy region '%v'; a function can only attach layers from its own region", [parts[3], region]),
	_pf_llar_fix, _pf_llar_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_fn
	some arn in _pf_lam_list(_pf_lam_get(name, "Layers"))
	parts := _pf_lam_arn(arn)
	parts[2] == "lambda"
	parts[3] != region
}
