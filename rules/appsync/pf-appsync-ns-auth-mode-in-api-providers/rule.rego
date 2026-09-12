package cdk_preflight

import rego.v1

# Judged only when the API is a sibling resource, so its auth providers are
# visible in this template.
_pf_nsauthmodeinapiproviders_providers(n) := {p.value.AuthType |
	some p in flatten_list(n, "Properties.EventConfig.AuthProviders")
}

violation contains make_diag_full("pf-appsync-ns-auth-mode-in-api-providers", "ERROR", name,
	"Properties.PublishAuthModes",
	sprintf("the namespace uses '%s' but API '%s' does not configure it in EventConfig.AuthProviders; the namespace create fails because the mode has no provider", [m.value.AuthType, api]),
	"Add the auth type to the API's EventConfig.AuthProviders, or use one that is already there",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-channelnamespace.html") if {
	some name in resources_of_type("AWS::AppSync::ChannelNamespace")
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::AppSync::Api")
	some f in ["PublishAuthModes", "SubscribeAuthModes"]
	some m in flatten_list(name, sprintf("Properties.%s", [f]))
	not m.value.AuthType in _pf_nsauthmodeinapiproviders_providers(api)
}
