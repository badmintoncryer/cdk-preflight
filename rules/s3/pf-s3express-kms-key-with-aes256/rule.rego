package cdk_preflight

import rego.v1

_pf_s3xkae_fix := "Either set SSEAlgorithm to aws:kms or drop KMSMasterKeyID"

_pf_s3xkae_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3express-directorybucket-serversideencryptionbydefault.html"

violation contains make_diag_full("pf-s3express-kms-key-with-aes256", "ERROR", name,
	sprintf("Properties.BucketEncryption.ServerSideEncryptionConfiguration.%d.ServerSideEncryptionByDefault.KMSMasterKeyID", [c.index]),
	"KMSMasterKeyID is set while SSEAlgorithm is AES256; the key is only accepted with SSEAlgorithm aws:kms",
	_pf_s3xkae_fix, _pf_s3xkae_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	some c in flatten_list(name, "Properties.BucketEncryption.ServerSideEncryptionConfiguration")
	is_object(c.value)
	d := object.get(c.value, "ServerSideEncryptionByDefault", {})
	is_object(d)
	object.get(d, "SSEAlgorithm", "") == "AES256"
	object.get(d, "KMSMasterKeyID", "__pf_absent") != "__pf_absent"
}
