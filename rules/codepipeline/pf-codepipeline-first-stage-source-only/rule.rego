package cdk_preflight

import rego.v1

# The bare engine's E3700 asks that the first stage hold a source action; the
# service also refuses anything else in it.
violation contains make_diag_full("pf-codepipeline-first-stage-source-only", "ERROR", name,
	sprintf("Properties.Stages.0.Actions.%v.ActionTypeId.Category", [ai]),
	sprintf("the first stage holds action '%v' of category '%v'; CreatePipeline fails with \"InvalidStructureException: Pipeline should start with a stage that only contains source actions\"", [an, cat]),
	"Move the non-source action to a later stage",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	st := _pf_cplib_stages(name)[0]
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	cat := _pf_cplib_category(a)
	cat != "Source"
	an := object.get(a, "Name", "")
}
