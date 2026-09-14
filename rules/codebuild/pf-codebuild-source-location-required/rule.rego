package cdk_preflight

import rego.v1

# The same check runs over Source and every SecondarySources entry: both come
# back with the bare "Project source location is required".
_pf_cbsrcloc_no_location := {"CODEPIPELINE": true, "NO_SOURCE": true}

violation contains make_diag_full("pf-codebuild-source-location-required", "ERROR", name,
	"Properties.Source.Location",
	sprintf("Source.Type is %s but no Location is set; CreateProject fails with \"Project source location is required\"", [t]),
	"Set Source.Location to the repository or bucket the build reads",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	s := _pf_codebuildlib_source(name)
	t := _pf_codebuildlib_str(s, "Type")
	not _pf_cbsrcloc_no_location[t]
	not _pf_codebuildlib_has(s, "Location")
}

violation contains make_diag_full("pf-codebuild-source-location-required", "ERROR", name,
	sprintf("Properties.SecondarySources[%d].Location", [item.index]),
	sprintf("A secondary source has Type %s but no Location; CreateProject fails with \"Project source location is required\"", [t]),
	"Set Location on the SecondarySources entry",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some item in flatten_list(name, "Properties.SecondarySources")
	t := item.value.Type
	is_string(t)
	not _pf_cbsrcloc_no_location[t]
	not _pf_codebuildlib_has(item.value, "Location")
}
