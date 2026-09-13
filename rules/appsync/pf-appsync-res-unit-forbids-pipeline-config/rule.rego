package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-res-unit-forbids-pipeline-config", "ERROR", name,
	"Properties.PipelineConfig",
	"Kind is UNIT but PipelineConfig is set; the resolver create rejects a pipeline configuration on a unit resolver",
	"Drop PipelineConfig, or use Kind: PIPELINE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	resolve(name, "Properties.Kind") == "UNIT"
	count(flatten_list(name, "Properties.PipelineConfig.Functions")) > 0
}
