package cdk_preflight

import rego.v1

_pf_resruntimerequirescode_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-res-runtime-requires-code", "ERROR", name,
	"Properties.Code",
	"Runtime is set but Code is not; the resolver create fails because an APPSYNC_JS runtime has no handler to run",
	"Set Properties.Code (or CodeS3Location), or drop Runtime and use mapping templates",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	is_object(resolve(name, "Properties.Runtime"))
	_pf_resruntimerequirescode_absent(name, "Code")
	_pf_resruntimerequirescode_absent(name, "CodeS3Location")
}
