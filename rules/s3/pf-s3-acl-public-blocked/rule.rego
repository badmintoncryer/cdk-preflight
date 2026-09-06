package cdk_preflight

import rego.v1

_pf_s3acp_fix := "Drop the public canned ACL, or turn off BlockPublicAcls for the bucket"

_pf_s3acp_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"

violation contains make_diag_full("pf-s3-acl-public-blocked", "ERROR", name, "Properties.AccessControl",
	sprintf("AccessControl '%v' is a public canned ACL; new buckets have Block Public Access on by default and CreateBucket rejects it", [acl]),
	_pf_s3acp_fix, _pf_s3acp_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	acl := resolve(name, "Properties.AccessControl")
	acl in {"PublicRead", "PublicReadWrite"}
	not _pf_s3acp_acls_unblocked(name)
}

_pf_s3acp_acls_unblocked(name) if {
	resolve(name, "Properties.PublicAccessBlockConfiguration.BlockPublicAcls") == false
}
