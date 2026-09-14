package cdk_preflight

import rego.v1

# PipelineType defaults to V1, and a V1 pipeline only runs in SUPERSEDED mode.
violation contains make_diag_full("pf-codepipeline-v1-execution-mode", "ERROR", name,
	"Properties.ExecutionMode",
	sprintf("ExecutionMode '%v' needs PipelineType V2 but the pipeline is V1; CreatePipeline fails with \"InvalidStructureException: QUEUED or PARALLEL mode can only be used with V2 pipelines\"", [m]),
	"Set PipelineType to V2, or leave ExecutionMode at SUPERSEDED",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-types.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	_pf_cplib_v1(name)
	m := _pf_cplib_get(_pf_cplib_props(name), "ExecutionMode")
	_pf_cplib_lit(m)
	m in {"QUEUED", "PARALLEL"}
}
