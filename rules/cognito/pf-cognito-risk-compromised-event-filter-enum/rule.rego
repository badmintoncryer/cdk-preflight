package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-risk-compromised-event-filter-enum", "ERROR", name,
	sprintf("Properties.CompromisedCredentialsRiskConfiguration.EventFilter.%d", [f.index]),
	sprintf("EventFilter has '%s'; the risk configuration call fails with \"Member must satisfy enum value set: [SIGN_IN, PASSWORD_CHANGE, SIGN_UP]\"", [v]),
	"Use SIGN_IN, PASSWORD_CHANGE and/or SIGN_UP",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolriskconfigurationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolRiskConfigurationAttachment")
	some f in flatten_list(name, "Properties.CompromisedCredentialsRiskConfiguration.EventFilter")
	v := f.value
	is_string(v)
	not v in {"SIGN_IN", "PASSWORD_CHANGE", "SIGN_UP"}
}
