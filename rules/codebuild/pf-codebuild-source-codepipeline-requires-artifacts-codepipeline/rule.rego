package cdk_preflight

import rego.v1

_pf_cbcpp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html"

_pf_cbcpp_msg := "CreateProject fails with \"Invalid input: when using CodePipeline both sourceType, and artifactType must be set to: CODEPIPELINE\""

violation contains make_diag_full("pf-codebuild-source-codepipeline-requires-artifacts-codepipeline", "ERROR", name,
	"Properties.Artifacts.Type",
	sprintf("Source.Type is CODEPIPELINE but Artifacts.Type is %s; %s", [a, _pf_cbcpp_msg]),
	"Set Artifacts.Type to CODEPIPELINE as well", _pf_cbcpp_url) if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	_pf_codebuildlib_source_type(name) == "CODEPIPELINE"
	a := _pf_codebuildlib_artifacts_type(name)
	a != "CODEPIPELINE"
}

violation contains make_diag_full("pf-codebuild-source-codepipeline-requires-artifacts-codepipeline", "ERROR", name,
	"Properties.Source.Type",
	sprintf("Artifacts.Type is CODEPIPELINE but Source.Type is %s; %s", [s, _pf_cbcpp_msg]),
	"Set Source.Type to CODEPIPELINE as well", _pf_cbcpp_url) if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	_pf_codebuildlib_artifacts_type(name) == "CODEPIPELINE"
	s := _pf_codebuildlib_source_type(name)
	s != "CODEPIPELINE"
}
