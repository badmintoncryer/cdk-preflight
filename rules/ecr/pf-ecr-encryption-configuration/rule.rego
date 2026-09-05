package cdk_preflight

import rego.v1

_pf_ecrenc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecr-repository-encryptionconfiguration.html"

_pf_ecrenc_fix := "Drop KmsKey for AES256, or set EncryptionType to KMS / KMS_DSSE and point KmsKey at a key in the deploy region"

_pf_ecrenc_config(name) := c if {
	c := object.get(input.resources[name].properties, "EncryptionConfiguration", null)
	is_object(c)
}

violation contains make_diag_full("pf-ecr-encryption-configuration", "ERROR", name,
	"Properties.EncryptionConfiguration.KmsKey",
	"EncryptionType is AES256 but KmsKey is set; the create call fails with \"Invalid encryption configuration: Encryption key should not be set for AES256 encryption.\"",
	_pf_ecrenc_fix, _pf_ecrenc_url) if {
	some t in _pf_ecrlib_repo_types
	some name in resources_of_type(t)
	c := _pf_ecrenc_config(name)
	object.get(c, "EncryptionType", null) == "AES256"
	not _pf_ecrlib_absent(c, "KmsKey")
}

# The key must exist in the repository's own region: ECR calls DescribeKey and
# KMS answers "Invalid arn <region>" for a key ARN from anywhere else.
violation contains make_diag_full("pf-ecr-encryption-configuration", "ERROR", name,
	"Properties.EncryptionConfiguration.KmsKey",
	sprintf("KmsKey is a key in region '%s' but the repository deploys to '%s'; the create call fails with a KmsException (\"Invalid arn %s\")", [parts[3], region, parts[3]]),
	_pf_ecrenc_fix, _pf_ecrenc_url) if {
	region := data.cdk_preflight.deploy_region
	some t in _pf_ecrlib_repo_types
	some name in resources_of_type(t)
	parts := _pf_ecrlib_arn(resolve(name, "Properties.EncryptionConfiguration.KmsKey"))
	parts[2] == "kms"
	parts[3] != region
}
