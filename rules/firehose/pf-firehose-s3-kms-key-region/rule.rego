package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-s3-kms-key-region", "ERROR", name,
	sprintf("%s.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN", [path]),
	sprintf("the KMS key is in %s but the stack deploys to %s; the stream create fails with \"KMS Key %s does not exist in the same region as the S3 bucket\"", [r, data.cdk_preflight.deploy_region, arn]),
	"Use a key in the same region as the destination bucket",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_KMSEncryptionConfig.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	kms := object.get(object.get(c, "EncryptionConfiguration", {}), "KMSEncryptionConfig", null)
	is_object(kms)
	arn := object.get(kms, "AWSKMSKeyARN", null)
	_pf_fhlib_lit(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) > 3
	r := parts[3]
	count(r) > 0
	r != data.cdk_preflight.deploy_region
}
