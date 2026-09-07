package cdk_preflight

import rego.v1

_pf_limgu_fix := "Set Code.ImageUri to the image in a private ECR repository"

_pf_limgu_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html"

violation contains make_diag_full("pf-lambda-image-requires-imageuri", "ERROR", name,
	"Properties.Code.ImageUri",
	"PackageType: Image without Code.ImageUri; a container-image function has nothing to deploy and the create is rejected",
	_pf_limgu_fix, _pf_limgu_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	code := _pf_lam_obj(props, "Code")
	object.get(props, "PackageType", "Zip") == "Image"
	not _pf_lam_has_key(code, "ImageUri")
}
