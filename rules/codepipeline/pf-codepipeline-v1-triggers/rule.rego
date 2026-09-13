package cdk_preflight

import rego.v1

# Triggers are V2-only; a V1 pipeline polls or uses a webhook instead.
violation contains make_diag_full("pf-codepipeline-v1-triggers", "ERROR", name,
	"Properties.Triggers",
	sprintf("the pipeline declares %d trigger(s) but is V1; CreatePipeline fails with \"InvalidStructureException: Triggers on tag can only be used with V2 pipelines\"", [n]),
	"Set PipelineType to V2, or replace the trigger with a webhook",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-types.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	_pf_cplib_v1(name)
	n := count(object.get(_pf_cplib_props(name), "Triggers", []))
	n > 0
}
