package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-risk-compromised-event-action-enum", "ERROR", name,
	"Properties.CompromisedCredentialsRiskConfiguration.Actions.EventAction",
	sprintf("EventAction '%s' is not valid here; the risk configuration call fails with \"Member must satisfy enum value set: [BLOCK, NO_ACTION]\"", [v]),
	"Use BLOCK or NO_ACTION (MFA actions belong to account takeover)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolriskconfigurationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolRiskConfigurationAttachment")
	v := _pf_coglib_str(_pf_coglib_g3(name, "CompromisedCredentialsRiskConfiguration", "Actions", "EventAction"))
	not v in {"BLOCK", "NO_ACTION"}
}
