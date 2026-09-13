package cdk_preflight

import rego.v1

# BeforeEntry / OnSuccess / OnFailure on a stage are V2-only.
violation contains make_diag_full("pf-codepipeline-v1-stage-conditions", "ERROR", name,
	sprintf("Properties.Stages.%v.%v", [si, gate]),
	sprintf("stage '%v' declares %v but the pipeline is V1; CreatePipeline fails with \"InvalidStageDeclarationException: Stage level conditions can only be used with V2 pipelines.\"", [sn, gate]),
	"Set PipelineType to V2, or drop the stage condition",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-types.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	_pf_cplib_v1(name)
	some si, st in _pf_cplib_stages(name)
	some gate in ["BeforeEntry", "OnSuccess", "OnFailure"]
	_pf_cplib_plain(object.get(st, gate, null))
	sn := object.get(st, "Name", "")
}
