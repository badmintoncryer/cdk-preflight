package cdk_preflight

import rego.v1

_pf_llrb_fix := "Grant lambda.amazonaws.com s3:GetObject and s3:GetObjectVersion on the content bucket"

_pf_llrb_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-self-managed-storage.html"

violation contains make_diag_full("pf-lambda-layer-reference-needs-bucket-policy", "ERROR", name,
	"Properties.Content.S3ObjectStorageMode",
	"REFERENCE content in a bucket with no policy for lambda.amazonaws.com; Lambda reads the object on every cold start and needs s3:GetObject and s3:GetObjectVersion",
	_pf_llrb_fix, _pf_llrb_url) if {
	some name in _pf_lam_layer
	c := _pf_lam_obj(_pf_lam_props(name), "Content")
	object.get(c, "S3ObjectStorageMode", "") == "REFERENCE"
	bkt := resolve(name, "Properties.Content.S3Bucket")
	bkt in resources_of_type("AWS::S3::Bucket")
	not _pf_llrb_policy(bkt)
}

_pf_llrb_policy(bkt) if {
	some p in resources_of_type("AWS::S3::BucketPolicy")
	resolve(p, "Properties.Bucket") == bkt
}
