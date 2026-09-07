package cdk_preflight

import rego.v1

_pf_s3eka_fix := "Set SSEAlgorithm to aws:kms (or aws:kms:dsse), or drop KMSMasterKeyID"

_pf_s3eka_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-serversideencryptionbydefault.html"

violation contains make_diag_full("pf-s3-encryption-kms-key-with-aes256", "ERROR", name,
	sprintf("Properties.BucketEncryption.ServerSideEncryptionConfiguration.%d.ServerSideEncryptionByDefault.KMSMasterKeyID", [c.index]),
	sprintf("KMSMasterKeyID is set while SSEAlgorithm is '%v'; the key is only accepted with aws:kms or aws:kms:dsse", [alg]),
	_pf_s3eka_fix, _pf_s3eka_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in flatten_list(name, "Properties.BucketEncryption.ServerSideEncryptionConfiguration")
	is_object(c.value)
	d := object.get(c.value, "ServerSideEncryptionByDefault", {})
	is_object(d)
	alg := object.get(d, "SSEAlgorithm", "")
	not alg in {"aws:kms", "aws:kms:dsse"}
	object.get(d, "KMSMasterKeyID", "__pf_absent") != "__pf_absent"
}
