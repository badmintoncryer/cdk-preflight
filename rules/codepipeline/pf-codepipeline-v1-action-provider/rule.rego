package cdk_preflight

import rego.v1

# Providers published after V2 shipped. The table lists only providers measured
# against CreatePipeline, so a newer V2-only provider costs a miss, not a false positive.
violation contains make_diag_full("pf-codepipeline-v1-action-provider", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.ActionTypeId.Provider", [si, ai]),
	sprintf("action '%v' uses the %v provider but the pipeline is V1; CreatePipeline fails with \"InvalidActionDeclarationException: %v Action can only be used with V2 pipelines.\"", [an, prov, prov]),
	"Set PipelineType to V2",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-types.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	_pf_cplib_v1(name)
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	prov := _pf_cplib_get(_pf_cplib_tid(a), "Provider")
	_pf_cplib_lit(prov)
	prov in _pf_cplib_v2_only_providers
	an := object.get(a, "Name", "")
}
