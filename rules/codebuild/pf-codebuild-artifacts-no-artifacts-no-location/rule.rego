package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-artifacts-no-artifacts-no-location", "ERROR", name,
	"Properties.Artifacts.Location",
	"Artifacts.Type is NO_ARTIFACTS but a Location is set; CreateProject fails with \"Invalid artifacts: artifact type NO_ARTIFACTS should have null location\"",
	"Drop Artifacts.Location, or set Artifacts.Type to S3",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-artifacts.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	a := _pf_codebuildlib_artifacts(name)
	_pf_codebuildlib_str(a, "Type") == "NO_ARTIFACTS"
	_pf_codebuildlib_has(a, "Location")
}
