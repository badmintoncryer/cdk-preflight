package cdk_preflight

import rego.v1

# A source action outside stage 0 is refused even when stage 0 has one too.
violation contains make_diag_full("pf-codepipeline-source-action-first-stage-only", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.ActionTypeId.Category", [si, ai]),
	sprintf("stage '%v' is not the first stage but holds source action '%v'; CreatePipeline fails with \"InvalidStructureException: Source actions can only be included in the first stage of the pipeline\"", [sn, an]),
	"Move the source action into the first stage",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	si > 0
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	_pf_cplib_category(a) == "Source"
	an := object.get(a, "Name", "")
	sn := object.get(st, "Name", "")
}
