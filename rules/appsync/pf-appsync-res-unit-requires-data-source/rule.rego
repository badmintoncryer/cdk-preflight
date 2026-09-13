package cdk_preflight

import rego.v1

_pf_resunitrequiresdatasource_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-res-unit-requires-data-source", "ERROR", name,
	"Properties.DataSourceName",
	"Kind is UNIT but DataSourceName is not set; the resolver create fails because a unit resolver has nothing to resolve against",
	"Set DataSourceName, or use Kind: PIPELINE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	resolve(name, "Properties.Kind") == "UNIT"
	_pf_resunitrequiresdatasource_absent(name, "DataSourceName")
}
