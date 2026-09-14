package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-project-name-length", "ERROR", name,
	"Properties.Name",
	sprintf("Name is %d characters; CreateProject fails with \"Project name length cannot be greater than 150 characters\"", [count(n)]),
	"Shorten the project name to 150 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	n := object.get(_pf_codebuildlib_props(name), "Name", null)
	_pf_codebuildlib_lit(n)
	count(n) > 150
}
