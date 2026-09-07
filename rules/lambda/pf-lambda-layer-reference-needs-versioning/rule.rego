package cdk_preflight

import rego.v1

_pf_llrv_fix := "Turn on versioning for the bucket that holds the layer content"

_pf_llrv_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-self-managed-storage.html"

violation contains make_diag_full("pf-lambda-layer-reference-needs-versioning", "ERROR", name,
	"Properties.Content.S3ObjectStorageMode",
	"REFERENCE content in a bucket without versioning; the mode pins an object version and the bucket cannot produce one",
	_pf_llrv_fix, _pf_llrv_url) if {
	some name in _pf_lam_layer
	c := _pf_lam_obj(_pf_lam_props(name), "Content")
	object.get(c, "S3ObjectStorageMode", "") == "REFERENCE"
	bkt := resolve(name, "Properties.Content.S3Bucket")
	bkt in resources_of_type("AWS::S3::Bucket")
	# Properties ごと無いバケットもあるので object.get で降りる
	bp := object.get(object.get(input.resources, bkt, {}), "properties", {})
	vc := object.get(bp, "VersioningConfiguration", {})
	object.get(vc, "Status", "") != "Enabled"
}
