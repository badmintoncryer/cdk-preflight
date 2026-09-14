package cdk_preflight

import rego.v1

# RunOrder is a 1-based position within the stage and tops out at 999.
violation contains make_diag_full("pf-codepipeline-run-order-range", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.RunOrder", [si, ai]),
	sprintf("RunOrder is %v; CreatePipeline fails with \"Value at 'pipeline.stages.N.member.actions.N.member.runOrder' failed to satisfy constraint: Member must have value greater than or equal to 1\"", [ro]),
	"Number the actions in the stage from 1",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ActionDeclaration.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	ro := to_number(object.get(a, "RunOrder", 1))
	ro < 1
}

violation contains make_diag_full("pf-codepipeline-run-order-range", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.RunOrder", [si, ai]),
	sprintf("RunOrder is %v; CreatePipeline fails with \"Value at 'pipeline.stages.N.member.actions.N.member.runOrder' failed to satisfy constraint: Member must have value less than or equal to 999\"", [ro]),
	"Keep RunOrder at 999 or below",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ActionDeclaration.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	ro := to_number(object.get(a, "RunOrder", 1))
	ro > 999
}
