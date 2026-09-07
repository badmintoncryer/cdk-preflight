package cdk_preflight

import rego.v1

_pf_s3xkal_fix := "Replace the alias with the KMS key id or key ARN"

_pf_s3xkal_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3express-directorybucket-serversideencryptionbydefault.html"

violation contains make_diag_full("pf-s3express-kms-key-alias", "ERROR", name,
	sprintf("Properties.BucketEncryption.ServerSideEncryptionConfiguration.%d.ServerSideEncryptionByDefault.KMSMasterKeyID", [c.index]),
	sprintf("KMSMasterKeyID '%v' is an alias; directory buckets accept only a KMS key id or key ARN", [kid]),
	_pf_s3xkal_fix, _pf_s3xkal_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	some c in flatten_list(name, "Properties.BucketEncryption.ServerSideEncryptionConfiguration")
	is_object(c.value)
	d := object.get(c.value, "ServerSideEncryptionByDefault", {})
	is_object(d)
	kid := object.get(d, "KMSMasterKeyID", "")
	is_string(kid)
	startswith(kid, "alias/")
}
