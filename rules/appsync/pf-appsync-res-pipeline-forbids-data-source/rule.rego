package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-res-pipeline-forbids-data-source", "ERROR", name,
	"Properties.DataSourceName",
	"Kind is PIPELINE but DataSourceName is set; the resolver create rejects a data source on a pipeline resolver, whose functions carry their own",
	"Drop DataSourceName, or use Kind: UNIT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	resolve(name, "Properties.Kind") == "PIPELINE"
	is_string(resolve(name, "Properties.DataSourceName"))
}
