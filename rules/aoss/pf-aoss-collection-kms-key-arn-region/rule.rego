package cdk_preflight

import rego.v1

# The schema pattern checks the ARN shape only - partition, Region, account and
# a uuid - never that the Region is the one the stack deploys into. The same
# hole as pf-aoss-encryption-policy-kms-arn-region, one property lower.
# data.cdk_preflight.deploy_region is injected only in enforce mode; the rule
# stays silent otherwise.

violation contains make_diag_full("pf-aoss-collection-kms-key-arn-region", "ERROR", name,
	"Properties.EncryptionConfig.KmsKeyArn",
	sprintf("KmsKeyArn names Region %v but the collection deploys to %v; CreateCollection answers \"Invalid kmsKeyId %v\"", [r, reg, arn]),
	"Reference a KMS key in the Region the collection deploys into, or set AWSOwnedKey to true",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchserverless-collection-encryptionconfig.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::Collection")
	reg := data.cdk_preflight.deploy_region
	is_string(reg)
	arn := resolve(name, "Properties.EncryptionConfig.KmsKeyArn")
	r := _pf_aoss_arn_region(arn)
	r != reg
}
