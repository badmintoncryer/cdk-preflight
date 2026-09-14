package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-source-no-source-no-location", "ERROR", name,
	"Properties.Source.Location",
	"Source.Type is NO_SOURCE but a Location is set; CreateProject fails with \"Invalid input: source location must be empty for source type NO_SOURCE\"",
	"Drop Source.Location, or name the source type the location belongs to",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	s := _pf_codebuildlib_source(name)
	_pf_codebuildlib_str(s, "Type") == "NO_SOURCE"
	_pf_codebuildlib_has(s, "Location")
}
