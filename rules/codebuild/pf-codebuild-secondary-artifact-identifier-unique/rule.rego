package cdk_preflight

import rego.v1

# A pairing, not a threshold: count() would force the pass fixture down to a
# single entry, which proves nothing about the duplicate.
violation contains make_diag_full("pf-codebuild-secondary-artifact-identifier-unique", "ERROR", name,
	"Properties.SecondaryArtifacts",
	sprintf("ArtifactIdentifier %s is used by more than one secondary artifact; CreateProject fails with \"Invalid input: artifactIdentifier cannot be duplicated\"", [v]),
	"Give each SecondaryArtifacts entry its own ArtifactIdentifier",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-artifacts.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	items := flatten_list(name, "Properties.SecondaryArtifacts")
	some a in items
	some b in items
	a.index < b.index
	v := a.value.ArtifactIdentifier
	is_string(v)
	b.value.ArtifactIdentifier == v
}
