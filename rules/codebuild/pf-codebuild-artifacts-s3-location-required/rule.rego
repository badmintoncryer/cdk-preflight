package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-artifacts-s3-location-required", "ERROR", name,
	"Properties.Artifacts",
	"Artifacts.Type is S3 but no Location is set; CreateProject fails with \"Invalid artifacts: location is required\"",
	"Set Artifacts.Location to the output bucket",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-artifacts.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	a := _pf_codebuildlib_artifacts(name)
	_pf_codebuildlib_str(a, "Type") == "S3"
	not _pf_codebuildlib_has(a, "Location")
}
