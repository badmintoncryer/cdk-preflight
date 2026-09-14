package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-secondary-source-identifier-unique", "ERROR", name,
	"Properties.SecondarySources",
	sprintf("SourceIdentifier %s is used by more than one secondary source; CreateProject fails with \"Invalid input: sourceIdentifier cannot be duplicated\"", [v]),
	"Give each SecondarySources entry its own SourceIdentifier",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	items := flatten_list(name, "Properties.SecondarySources")
	some a in items
	some b in items
	a.index < b.index
	v := a.value.SourceIdentifier
	is_string(v)
	b.value.SourceIdentifier == v
}
