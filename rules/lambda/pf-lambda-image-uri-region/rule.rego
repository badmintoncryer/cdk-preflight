package cdk_preflight

import rego.v1

_pf_limgr_fix := "Push the image to an ECR repository in the same region as the function"

_pf_limgr_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-images.html"

violation contains make_diag_full("pf-lambda-image-uri-region", "ERROR", name,
	"Properties.Code.ImageUri",
	sprintf("image region '%v' is not the deploy region '%v'; Lambda pulls container images from its own region only", [parts[3], region]),
	_pf_limgr_fix, _pf_limgr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	code := _pf_lam_obj(props, "Code")
	uri := _pf_lam_str(code, "ImageUri")
	_pf_lam_lit(uri)
	parts := split(split(uri, "/")[0], ".")
	count(parts) > 4
	startswith(parts[2], "ecr")
	parts[3] != region
}
