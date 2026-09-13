package cdk_preflight

import rego.v1

# The failure exit gate is configured one way or the other.
violation contains make_diag_full("pf-codepipeline-stage-on-failure-result-xor-conditions", "ERROR", name,
	sprintf("Properties.Stages.%v.OnFailure", [si]),
	sprintf("stage '%v' sets both OnFailure.Result and OnFailure.Conditions; CreatePipeline fails with \"InvalidStageDeclarationException: The following stage cannot have a failure exit gate configured with both top level result and conditions: '%v\"", [sn, sn]),
	"Keep either OnFailure.Result or OnFailure.Conditions, not both",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	of := object.get(st, "OnFailure", null)
	_pf_cplib_plain(of)
	not _pf_cplib_absent(of, "Result")
	not _pf_cplib_absent(of, "Conditions")
	sn := object.get(st, "Name", "")
}
