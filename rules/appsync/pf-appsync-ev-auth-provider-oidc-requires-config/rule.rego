package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ev-auth-provider-oidc-requires-config", "ERROR", name,
	"Properties.EventConfig.AuthProviders",
	"an EventConfig.AuthProviders entry is OPENID_CONNECT but carries no OpenIDConnectConfig; the API create fails because AppSync has nothing to validate tokens against",
	"Set OpenIDConnectConfig on that auth provider, or use a different AuthType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-api.html") if {
	some name in resources_of_type("AWS::AppSync::Api")
	some p in flatten_list(name, "Properties.EventConfig.AuthProviders")
	p.value.AuthType == "OPENID_CONNECT"
	object.get(p.value, "OpenIDConnectConfig", "__pf_absent") == "__pf_absent"
}
