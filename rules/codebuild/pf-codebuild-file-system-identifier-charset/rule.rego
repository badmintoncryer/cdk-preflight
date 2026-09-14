package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-file-system-identifier-charset", "ERROR", name,
	"Properties.Environment.PrivilegedMode",
	"FileSystemLocations mounts a file system into the build container, which needs the privileged Docker daemon; CreateProject fails with \"Privileged Mode has to be set for projects with File System Locations\"",
	"Set Environment.PrivilegedMode to true, or drop FileSystemLocations",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-projectfilesystemlocation.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	count(flatten_list(name, "Properties.FileSystemLocations")) > 0
	not _pf_codebuildlib_true(object.get(_pf_codebuildlib_env(name), "PrivilegedMode", null))
}
