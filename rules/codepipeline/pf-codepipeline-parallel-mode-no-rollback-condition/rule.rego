package cdk_preflight

import rego.v1

# A PARALLEL pipeline runs every execution independently, so there is no
# previous execution to roll back to.
violation contains make_diag_full("pf-codepipeline-parallel-mode-no-rollback-condition", "ERROR", name,
	sprintf("Properties.Stages.%v.OnFailure.Result", [si]),
	sprintf("stage '%v' exits failure with ROLLBACK while the pipeline's ExecutionMode is PARALLEL; CreatePipeline fails with \"InvalidStageDeclarationException: Failure conditions with rollback result type cannot be added to a PARALLEL pipeline.\"", [object.get(st, "Name", "")]),
	"Switch ExecutionMode to QUEUED or SUPERSEDED, or drop the ROLLBACK result",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/stage-conditions.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	props := _pf_cplib_props(name)
	object.get(props, "ExecutionMode", "") == "PARALLEL"
	some si, st in _pf_cplib_stages(name)
	of := object.get(st, "OnFailure", {})
	_pf_cplib_plain(of)
	object.get(of, "Result", "") == "ROLLBACK"
}
