package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-res-pipeline-functions-max", "ERROR", name,
	"Properties.PipelineConfig.Functions",
	sprintf("the pipeline lists %d functions; the resolver create fails because a pipeline is limited to 10", [count(fs)]),
	"Keep 10 or fewer functions in the pipeline",
	"https://docs.aws.amazon.com/general/latest/gr/appsync.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	fs := flatten_list(name, "Properties.PipelineConfig.Functions")
	count(fs) > 10
}
