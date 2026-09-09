package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-recovery-admin-only-alone", "ERROR", name,
	sprintf("Properties.AccountRecoverySetting.RecoveryMechanisms.%d", [m.index]),
	"admin_only is combined with other recovery mechanisms; the pool create fails with \"Account Recovery Setting cannot use admin_only setting with any other recovery mechanisms.\"",
	"Use admin_only on its own, or drop it and keep the verified_* mechanisms",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	ms := flatten_list(name, "Properties.AccountRecoverySetting.RecoveryMechanisms")
	count(ms) > 1
	some m in ms
	_pf_coglib_at(m.value, "Name") == "admin_only"
}
