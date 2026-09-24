package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-s3-encryption-kms-key-required", "ERROR", name,
	"Properties.ArtifactConfig.S3Encryption.KmsKeyArn",
	"ArtifactConfig.S3Encryption.EncryptionMode is SSE_KMS but no KmsKeyArn is given; SSE_KMS always means a customer-managed key here, and CreateCanary answers \"KmsKeyArn must be specified with SSE_KMS encryption mode\"",
	"Add ArtifactConfig.S3Encryption.KmsKeyArn, or use EncryptionMode SSE_S3",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-s3encryption.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	resolve(name, "Properties.ArtifactConfig.S3Encryption.EncryptionMode") == "SSE_KMS"
	_pf_synlib_absent(name, ["ArtifactConfig", "S3Encryption", "KmsKeyArn"])
}
