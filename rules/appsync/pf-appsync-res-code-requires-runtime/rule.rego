package cdk_preflight

import rego.v1

_pf_rescoderequiresruntime_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-res-code-requires-runtime", "ERROR", name,
	"Properties.Runtime",
	"Code is set but Runtime is not; the resolver create fails because AppSync does not know which runtime to run the handler on",
	"Set Properties.Runtime to { Name: APPSYNC_JS, RuntimeVersion: 1.0.0 }",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	is_string(resolve(name, "Properties.Code"))
	_pf_rescoderequiresruntime_absent(name, "Runtime")
}
