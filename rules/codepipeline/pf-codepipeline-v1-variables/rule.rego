package cdk_preflight

import rego.v1

# Pipeline variables are V2-only.
violation contains make_diag_full("pf-codepipeline-v1-variables", "ERROR", name,
	"Properties.Variables",
	sprintf("the pipeline declares %d variable(s) but is V1; CreatePipeline fails with \"InvalidStructureException: Pipeline variable can only be used with V2 pipelines\"", [n]),
	"Set PipelineType to V2, or drop the pipeline variables",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-types.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	_pf_cplib_v1(name)
	_pf_unconditional_items(object.get(_pf_cplib_props(name), "Variables", []))
	n := count(object.get(_pf_cplib_props(name), "Variables", []))
	n > 0
}
