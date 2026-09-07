package cdk_preflight

import rego.v1

_pf_limgz_fix := "Use Code.S3Bucket/S3Key or Code.ZipFile for a .zip function"

_pf_limgz_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"

violation contains make_diag_full("pf-lambda-zip-no-imageuri", "ERROR", name,
	"Properties.Code.ImageUri",
	"Code.ImageUri on a .zip function; the image URI is only read when PackageType is Image",
	_pf_limgz_fix, _pf_limgz_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	code := _pf_lam_obj(props, "Code")
	object.get(props, "PackageType", "Zip") != "Image"
	_pf_lam_has_key(code, "ImageUri")
}
