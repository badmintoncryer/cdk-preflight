package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode; the rule
# stays silent otherwise. KMS rejects the ARN before it looks the key up, so
# this fires whether or not the key exists.

violation contains make_diag_full("pf-opensearch-kms-key-region", "ERROR", name,
	"Properties.EncryptionAtRestOptions.KmsKeyId",
	sprintf("the KMS key is in %v but the domain deploys to %v; CreateDomain answers \"Error in Accessing KmsKeyID with details:Invalid arn %v\"", [r, reg, r]),
	"Reference a key in the Region the domain deploys into, or drop KmsKeyId to use the service-managed key",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-encryptionatrestoptions.html") if {
	some name in _pf_os_domains
	reg := data.cdk_preflight.deploy_region
	is_string(reg)
	r := _pf_os_arn_region(_pf_os_opt(name, "EncryptionAtRestOptions", "KmsKeyId"))
	r != reg
}
