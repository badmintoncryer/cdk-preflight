package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise. A key in another partition also
# names another region, so this covers the cross-partition case too.
violation contains make_diag_full("pf-eks-cluster-encryption-kms-key-region", "ERROR", name,
	"Properties.EncryptionConfig",
	sprintf("the encryption key is in %v but the cluster deploys to %v (\"The keyArn for encryptionConfig is scoped to invalid aws region.\")", [kr, region]),
	"Point EncryptionConfig.Provider.KeyArn at a key in the cluster's region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-encryptionconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some ec in flatten_list(name, "Properties.EncryptionConfig")
	arn := object.get(ec.value, ["Provider", "KeyArn"], "")
	_pf_ekslib_lit(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "kms"
	kr := parts[3]
	kr != ""
	kr != region
}
