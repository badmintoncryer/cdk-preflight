package cdk_preflight

import rego.v1

# An action whose Region differs from the pipeline's own needs one artifact
# store per region, which is what the plural ArtifactStores is for. The singular
# ArtifactStore cannot express it. data.cdk_preflight.deploy_region is injected
# only in enforce mode with a concrete region; the rule skips otherwise, and a
# Region equal to the deploy region is not cross-region at all.
violation contains make_diag_full("pf-codepipeline-cross-region-action-needs-store", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.Region", [si, ai]),
	sprintf("action '%v' runs in '%v' but the pipeline deploys to '%v' with a single ArtifactStore; CreatePipeline fails with \"Your pipeline contains actions in more than one region. Use 'pipeline.artifactStores' instead of 'pipeline.artifactStore' to declare an artifact store, such as an artifact bucket, for each region where you have an action.\"", [an, r, region]),
	"Replace ArtifactStore with an ArtifactStores entry for each region the pipeline's actions run in",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/actions-create-cross-region.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	props := _pf_cplib_props(name)
	_pf_cplib_plain(object.get(props, "ArtifactStore", null))
	_pf_cplib_absent(props, "ArtifactStores")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r := _pf_cplib_get(a, "Region")
	_pf_cplib_lit(r)
	r != region
	an := object.get(a, "Name", "")
}
