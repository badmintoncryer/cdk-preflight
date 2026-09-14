package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-project-description-length", "ERROR", name,
	"Properties.Description",
	sprintf("Description is %d characters; CreateProject fails with \"Max description length is 255\"", [count(d)]),
	"Shorten the description to 255 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	d := object.get(_pf_codebuildlib_props(name), "Description", null)
	_pf_codebuildlib_lit(d)
	count(d) > 255
}
