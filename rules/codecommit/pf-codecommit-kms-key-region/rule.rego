package cdk_preflight

import rego.v1

# The ARN shape is all the schema checks; which region it names is only
# resolvable against the stack's own region.
violation contains make_diag_full("pf-codecommit-kms-key-region", "ERROR", name,
	"Properties.KmsKeyId",
	sprintf("The KMS key is in '%s' but the repository deploys to '%s'; CreateRepository looks the key up in its own region and fails with \"KMS key %s is not found\"", [kr, region, k]),
	"Reference a KMS key in the deploy region, or drop KmsKeyId to use the AWS managed key",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_CreateRepository.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	k := resolve(name, "Properties.KmsKeyId")
	parts := _pf_cclib_arn(k)
	parts[2] == "kms"
	kr := parts[3]
	kr != ""
	kr != region
}
