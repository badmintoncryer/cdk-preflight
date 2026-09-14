package cdk_preflight

import rego.v1

# Actions that carry no Region run in the pipeline's own region, so the
# cross-region ArtifactStores list must always include an entry for it.
# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise, and skips a list whose regions are
# all tokens.
violation contains make_diag_full("pf-codepipeline-artifact-stores-region-of-pipeline", "ERROR", name,
	"Properties.ArtifactStores",
	sprintf("ArtifactStores covers %v but the pipeline deploys to '%v'; CreatePipeline fails with \"Your pipeline must have an artifact store, such as an artifact bucket, for each region where you have an action. The following region is missing in 'pipeline.artifactStores': %v.\"", [concat(", ", sort(regions)), region, region]),
	sprintf("Add an ArtifactStores entry whose Region is %v", [region]),
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	stores := object.get(_pf_cplib_props(name), "ArtifactStores", [])
	regions := {r | some e in stores; r := object.get(e, "Region", ""); _pf_cplib_lit(r)}
	count(regions) == count(stores)
	count(regions) > 0
	not region in regions
}
