package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-s3-encryption-mode-enum", "ERROR", name,
	"Properties.ArtifactConfig.S3Encryption.EncryptionMode",
	sprintf("ArtifactConfig.S3Encryption.EncryptionMode is '%s'; the only values the service takes are SSE_S3 and SSE_KMS (underscores, not the hyphenated spelling S3 itself uses), and CreateCanary answers \"failed to satisfy constraint: Member must satisfy enum value set: [SSE_KMS, SSE_S3]\"", [mode]),
	"Write SSE_S3 or SSE_KMS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-s3encryption.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	mode := _pf_synlib_str(name, ["ArtifactConfig", "S3Encryption", "EncryptionMode"])
	not mode in _pf_synlib_encryption_modes
}
