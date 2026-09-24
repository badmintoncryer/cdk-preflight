package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode; the rule
# stays silent otherwise (warn mode and Region-agnostic apps).

violation contains make_diag_full("pf-aoss-encryption-policy-kms-arn-region", "ERROR", name,
	"Properties.Policy.KmsARN",
	sprintf("KmsARN names Region %v but the policy deploys to %v; CreateSecurityPolicy answers \"Invalid kmsKeyId %v\"", [r, reg, arn]),
	"Reference a KMS key in the Region the policy deploys into, or set AWSOwnedKey to true",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html") if {
	some name in _pf_aoss_enc
	reg := data.cdk_preflight.deploy_region
	is_string(reg)
	d := _pf_aoss_doc(name)
	is_object(d)
	arn := object.get(d, "KmsARN", null)
	r := _pf_aoss_arn_region(arn)
	r != reg
}
