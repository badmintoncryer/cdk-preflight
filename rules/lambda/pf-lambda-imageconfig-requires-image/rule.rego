package cdk_preflight

import rego.v1

_pf_limgc_fix := "Drop ImageConfig, or switch the function to PackageType: Image"

_pf_limgc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"

violation contains make_diag_full("pf-lambda-imageconfig-requires-image", "ERROR", name,
	"Properties.ImageConfig",
	"ImageConfig on a .zip function; the entry point overrides only exist for container images",
	_pf_limgc_fix, _pf_limgc_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	_pf_lam_has_key(props, "ImageConfig")
	object.get(props, "PackageType", "Zip") != "Image"
}
