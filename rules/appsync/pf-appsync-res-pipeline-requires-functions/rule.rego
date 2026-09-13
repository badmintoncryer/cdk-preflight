package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-res-pipeline-requires-functions", "ERROR", name,
	"Properties.PipelineConfig",
	"Kind is PIPELINE but PipelineConfig.Functions is empty; the resolver create fails because a pipeline has no functions to run",
	"List the function ids in PipelineConfig.Functions, or use Kind: UNIT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	resolve(name, "Properties.Kind") == "PIPELINE"
	count(flatten_list(name, "Properties.PipelineConfig.Functions")) == 0
}
