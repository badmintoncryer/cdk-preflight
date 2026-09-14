package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-secondary-sources-max-12", "ERROR", name,
	"Properties.SecondarySources",
	sprintf("%d secondary sources are declared; CreateProject fails with \"Invalid input: the maximum number of secondary sources is 12\"", [n]),
	"Keep SecondarySources to 12 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	n := count(flatten_list(name, "Properties.SecondarySources"))
	n > 12
}
