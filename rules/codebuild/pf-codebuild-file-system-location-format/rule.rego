package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-file-system-location-format", "ERROR", name,
	"Properties.FileSystemLocations",
	sprintf("FileSystemLocations Location %s carries no directory; CreateProject fails with \"File System Location is invalid, should be in the form 'FileSystemDNS':'FileSystemDirectory'\"", [loc]),
	"Write the location as the EFS DNS name, a colon, and the directory (e.g. fs-0123.efs.us-east-1.amazonaws.com:/)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-projectfilesystemlocation.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some item in flatten_list(name, "Properties.FileSystemLocations")
	loc := item.value.Location
	is_string(loc)
	not contains(loc, ":")
}
