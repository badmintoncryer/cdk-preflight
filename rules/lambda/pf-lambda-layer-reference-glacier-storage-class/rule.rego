package cdk_preflight

import rego.v1

_pf_llrg_fix := "Keep the layer object out of Glacier storage classes"

_pf_llrg_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-self-managed-storage.html"

_pf_llrg_glacier := {"GLACIER", "DEEP_ARCHIVE", "GLACIER_IR"}

violation contains make_diag_full("pf-lambda-layer-reference-glacier-storage-class", "WARN", name,
	"Properties.Content.S3ObjectStorageMode",
	"REFERENCE content in a bucket that transitions objects to Glacier; an archived object cannot be read at cold start",
	_pf_llrg_fix, _pf_llrg_url) if {
	some name in _pf_lam_layer
	c := _pf_lam_obj(_pf_lam_props(name), "Content")
	object.get(c, "S3ObjectStorageMode", "") == "REFERENCE"
	bkt := resolve(name, "Properties.Content.S3Bucket")
	bp := object.get(object.get(input.resources, bkt, {}), "properties", {})
	lc := object.get(bp, "LifecycleConfiguration", {})
	some rule in _pf_lam_list(object.get(lc, "Rules", []))
	some t in _pf_lam_list(object.get(rule, "Transitions", []))
	object.get(t, "StorageClass", "") in _pf_llrg_glacier
}
