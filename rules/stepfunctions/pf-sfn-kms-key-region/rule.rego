package cdk_preflight

import rego.v1

_pf_sfnkms_url := "https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html"

_pf_sfnkms_fix := "Use a KMS key created in the same region as the state machine (Fn::GetAtt Key.Arn of a key in this stack)"

# Region comparison needs the deploy region, which only this pack sees
# (data.cdk_preflight.deploy_region is defined in enforce mode; the rule
# skips without it).
violation contains make_diag_full("pf-sfn-kms-key-region", "ERROR", name,
	"Properties.EncryptionConfiguration.KmsKeyId",
	sprintf("KmsKeyId is a key in '%s' but the deploy region is '%s'; KMS rejects the key at create time with \"InvalidEncryptionConfiguration: Invalid arn %s\"", [parts[3], region, parts[3]]),
	_pf_sfnkms_fix, _pf_sfnkms_url) if {
	region := data.cdk_preflight.deploy_region
	some rt in ["AWS::StepFunctions::StateMachine", "AWS::StepFunctions::Activity"]
	some name in resources_of_type(rt)
	arn := resolve(name, "Properties.EncryptionConfiguration.KmsKeyId")
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "kms"
	parts[3] != ""
	parts[3] != region
}
