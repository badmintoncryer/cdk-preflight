package cdk_preflight

import rego.v1

_pf_efskms_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_CreateFileSystem.html"

_pf_efskms_fix := "Set Encrypted: true next to KmsKeyId and point it at a key in the same region as the file system"

violation contains make_diag_full("pf-efs-kms-key", "ERROR", name,
	"Properties.KmsKeyId",
	"KmsKeyId is set but Encrypted is not true; CreateFileSystem fails with \"The encrypted parameter must be set to true to create an encrypted file system.\"",
	_pf_efskms_fix, _pf_efskms_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	not _pf_efslib_absent(name, "KmsKeyId")
	not _pf_efskms_encrypted(name)
}

# resolve() is undefined for an absent property, so "not true" needs its own helper.
_pf_efskms_encrypted(name) if resolve(name, "Properties.Encrypted") == true

violation contains make_diag_full("pf-efs-kms-key", "ERROR", name,
	"Properties.KmsKeyId",
	sprintf("the key is in region '%s' but the file system deploys to '%s'; CreateFileSystem fails with \"Invalid KMS key ID (unexpected region)\"", [parts[3], region]),
	_pf_efskms_fix, _pf_efskms_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::EFS::FileSystem")
	parts := _pf_efslib_arn(resolve(name, "Properties.KmsKeyId"))
	parts[2] == "kms"
	parts[3] != region
}
