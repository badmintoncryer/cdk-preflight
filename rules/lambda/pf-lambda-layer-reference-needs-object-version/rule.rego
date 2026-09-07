package cdk_preflight

import rego.v1

_pf_llro_fix := "Set Content.S3ObjectVersion alongside S3ObjectStorageMode: REFERENCE"

_pf_llro_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-self-managed-storage.html"

violation contains make_diag_full("pf-lambda-layer-reference-needs-object-version", "ERROR", name,
	"Properties.Content.S3ObjectVersion",
	"S3ObjectStorageMode REFERENCE without S3ObjectVersion; the layer keeps reading the object from the bucket, so it has to pin the exact version",
	_pf_llro_fix, _pf_llro_url) if {
	some name in _pf_lam_layer
	c := _pf_lam_obj(_pf_lam_props(name), "Content")
	object.get(c, "S3ObjectStorageMode", "") == "REFERENCE"
	not _pf_lam_has_key(c, "S3ObjectVersion")
}
