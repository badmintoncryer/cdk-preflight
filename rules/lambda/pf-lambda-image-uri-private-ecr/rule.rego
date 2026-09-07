package cdk_preflight

import rego.v1

_pf_limgp_fix := "Push the image to a private ECR repository in this account and region"

_pf_limgp_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-images.html"

violation contains make_diag_full("pf-lambda-image-uri-private-ecr", "ERROR", name,
	"Properties.Code.ImageUri",
	sprintf("ImageUri '%v' is not a private ECR repository; Lambda cannot pull from ECR Public or Docker Hub", [uri]),
	_pf_limgp_fix, _pf_limgp_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	code := _pf_lam_obj(props, "Code")
	uri := _pf_lam_str(code, "ImageUri")
	_pf_lam_lit(uri)
	not regex.match(`^[0-9]{12}\.dkr\.ecr[a-z-]*\.[a-z0-9-]+\.amazonaws\.com/`, uri)
}
