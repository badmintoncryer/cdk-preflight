package cdk_preflight

import rego.v1

_pf_lssm_fix := "Drop Code.S3ObjectStorageMode from a container-image function"

_pf_lssm_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-self-managed-storage.html"

violation contains make_diag_full("pf-lambda-s3-storage-mode-zip-only", "ERROR", name,
	"Properties.Code.S3ObjectStorageMode",
	"Code.S3ObjectStorageMode on a container-image function; self-managed storage is a .zip deployment option",
	_pf_lssm_fix, _pf_lssm_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	object.get(props, "PackageType", "Zip") == "Image"
	_pf_lam_has_key(_pf_lam_obj(props, "Code"), "S3ObjectStorageMode")
}
