package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-secondary-sources-identifier-required", "ERROR", name,
	sprintf("Properties.SecondarySources[%d]", [item.index]),
	"A secondary source has no SourceIdentifier; CreateProject fails with \"Invalid input: sourceIdentifier is required for secondary sources\"",
	"Set SourceIdentifier on the entry; the buildspec and SecondarySourceVersions name the source by it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some item in flatten_list(name, "Properties.SecondarySources")
	not _pf_codebuildlib_has(item.value, "SourceIdentifier")
}
