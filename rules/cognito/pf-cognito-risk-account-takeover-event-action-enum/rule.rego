package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-risk-account-takeover-event-action-enum", "ERROR", name,
	sprintf("Properties.AccountTakeoverRiskConfiguration.Actions.%s.EventAction", [k]),
	sprintf("%s.EventAction '%s' is not valid; the risk configuration call fails with \"Member must satisfy enum value set: [MFA_IF_CONFIGURED, BLOCK, NO_ACTION, MFA_REQUIRED]\"", [k, v]),
	"Use BLOCK, MFA_IF_CONFIGURED, MFA_REQUIRED or NO_ACTION",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolriskconfigurationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolRiskConfigurationAttachment")
	some k in ["LowAction", "MediumAction", "HighAction"]
	a := _pf_coglib_g3(name, "AccountTakeoverRiskConfiguration", "Actions", k)
	v := _pf_coglib_str(_pf_coglib_at(a, "EventAction"))
	not v in {"BLOCK", "MFA_IF_CONFIGURED", "MFA_REQUIRED", "NO_ACTION"}
}
