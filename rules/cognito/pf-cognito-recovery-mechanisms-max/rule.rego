package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-recovery-mechanisms-max", "ERROR", name,
	"Properties.AccountRecoverySetting.RecoveryMechanisms",
	sprintf("%d recovery mechanisms are configured; the pool create fails with \"Member must have length less than or equal to 2\"", [count(ms)]),
	"Keep at most two recovery mechanisms",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	ms := flatten_list(name, "Properties.AccountRecoverySetting.RecoveryMechanisms")
	count(ms) > 2
}
