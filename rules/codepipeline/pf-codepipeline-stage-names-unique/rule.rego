package cdk_preflight

import rego.v1

# The engine's F3037 catches duplicate action names inside one stage; duplicate
# stage names are a different check and only the service makes it.
violation contains make_diag_full("pf-codepipeline-stage-names-unique", "ERROR", name,
	sprintf("Properties.Stages.%v.Name", [sj]),
	sprintf("stage name '%v' is used by stages %d and %d; CreatePipeline fails with \"InvalidStageDeclarationException: Stage name '%v' is used more than once\"", [sn, si, sj, sn]),
	"Give every stage a distinct name",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some sj, st2 in _pf_cplib_stages(name)
	si < sj
	sn := _pf_cplib_get(st, "Name")
	_pf_cplib_lit(sn)
	sn == _pf_cplib_get(st2, "Name")
}
