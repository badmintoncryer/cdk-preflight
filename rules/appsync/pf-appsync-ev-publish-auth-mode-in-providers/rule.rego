package cdk_preflight

import rego.v1

_pf_evpublishauthmodeinproviders_providers(n) := {p.value.AuthType |
	some p in flatten_list(n, "Properties.EventConfig.AuthProviders")
}

violation contains make_diag_full("pf-appsync-ev-publish-auth-mode-in-providers", "ERROR", name,
	"Properties.EventConfig.DefaultPublishAuthModes",
	sprintf("DefaultPublishAuthModes uses '%s' but EventConfig.AuthProviders does not configure it; the API create fails because the mode has no provider to validate against", [m.value.AuthType]),
	"Add the auth type to EventConfig.AuthProviders, or use one that is already there",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-api.html") if {
	some name in resources_of_type("AWS::AppSync::Api")
	some m in flatten_list(name, "Properties.EventConfig.DefaultPublishAuthModes")
	not m.value.AuthType in _pf_evpublishauthmodeinproviders_providers(name)
}
