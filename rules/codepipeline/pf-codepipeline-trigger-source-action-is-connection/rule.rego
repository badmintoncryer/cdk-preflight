package cdk_preflight

import rego.v1

# One service check covers both halves: the named action has to exist and it has
# to be a CodeStarSourceConnection source.
violation contains make_diag_full("pf-codepipeline-trigger-source-action-is-connection", "ERROR", name,
	sprintf("Properties.Triggers.%v.GitConfiguration.SourceActionName", [ti]),
	sprintf("SourceActionName '%v' is not a CodeStarSourceConnection source action of this pipeline; CreatePipeline fails with \"InvalidStructureException: Triggers for connections must reference a CodeStarSourceConnection action.\"", [san]),
	"Point SourceActionName at a CodeStarSourceConnection source action in the pipeline",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	not _pf_cplib_dynamic_action_name(name)
	some ti, t in object.get(_pf_cplib_props(name), "Triggers", [])
	g := _pf_cplib_get(t, "GitConfiguration")
	_pf_cplib_plain(g)
	san := _pf_cplib_get(g, "SourceActionName")
	_pf_cplib_lit(san)
	not _pf_cplib_connection_actions(name)[san]
}
