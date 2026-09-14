package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-secondary-artifacts-identifier-required", "ERROR", name,
	sprintf("Properties.SecondaryArtifacts[%d]", [item.index]),
	"A secondary artifact has no ArtifactIdentifier; CreateProject fails with \"Invalid input: artifactIdentifier is required for secondary artifacts\"",
	"Set ArtifactIdentifier on the entry; the buildspec names the artifact by it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-artifacts.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some item in flatten_list(name, "Properties.SecondaryArtifacts")
	not _pf_codebuildlib_has(item.value, "ArtifactIdentifier")
}
