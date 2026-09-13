package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-badge-not-with-codepipeline-source", "ERROR", name,
	"Properties.BadgeEnabled",
	"BadgeEnabled is true on a CODEPIPELINE source; CreateProject fails with \"Build badges are not supported for CodePipeline source\"",
	"Drop BadgeEnabled from the project CodePipeline drives",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	_pf_codebuildlib_true(object.get(_pf_codebuildlib_props(name), "BadgeEnabled", null))
	_pf_codebuildlib_source_type(name) == "CODEPIPELINE"
}
