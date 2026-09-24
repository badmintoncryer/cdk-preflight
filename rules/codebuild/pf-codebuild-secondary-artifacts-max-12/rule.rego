package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-secondary-artifacts-max-12", "ERROR", name,
	"Properties.SecondaryArtifacts",
	sprintf("%d secondary artifacts are declared; CreateProject fails with \"Invalid input: the maximum number of artifact definitions in secondaryArtifacts is 12\"", [n]),
	"Keep SecondaryArtifacts to 12 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	_pf_countable_list(name, "Properties.SecondaryArtifacts")
	n := count(flatten_list(name, "Properties.SecondaryArtifacts"))
	n > 12
}
