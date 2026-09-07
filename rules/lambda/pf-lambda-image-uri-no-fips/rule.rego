package cdk_preflight

import rego.v1

_pf_limgf_fix := "Use the standard ECR endpoint (dkr.ecr) rather than dkr.ecr-fips"

_pf_limgf_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-images.html"

violation contains make_diag_full("pf-lambda-image-uri-no-fips", "ERROR", name,
	"Properties.Code.ImageUri",
	"an ImageUri on an ECR FIPS endpoint; Lambda pulls images through the standard ECR endpoint only",
	_pf_limgf_fix, _pf_limgf_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	code := _pf_lam_obj(props, "Code")
	uri := _pf_lam_str(code, "ImageUri")
	_pf_lam_lit(uri)
	contains(uri, ".dkr.ecr-fips.")
}
