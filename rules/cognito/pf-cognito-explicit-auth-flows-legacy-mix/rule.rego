package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-explicit-auth-flows-legacy-mix", "ERROR", name,
	sprintf("Properties.ExplicitAuthFlows.%d", [b.index]),
	sprintf("ExplicitAuthFlows mixes the legacy name '%s' with ALLOW_ names; the client create fails with \"Auth flow name with prefix 'ALLOW' cannot be used with legacy auth flow names.\"", [b.value]),
	"Use the ALLOW_* names only (ADMIN_NO_SRP_AUTH becomes ALLOW_ADMIN_USER_PASSWORD_AUTH)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	fs := flatten_list(name, "Properties.ExplicitAuthFlows")
	some a in fs
	is_string(a.value)
	startswith(a.value, "ALLOW_")
	some b in fs
	is_string(b.value)
	not startswith(b.value, "ALLOW_")
}
