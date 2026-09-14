package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-environment-variable-name-reserved", "ERROR", name,
	"Properties.Environment.EnvironmentVariables",
	sprintf("Environment variable %s uses the CODEBUILD_ prefix CodeBuild reserves for the build agent; CreateProject fails with \"No user environment variables can start with CODEBUILD_\"", [v]),
	"Rename the variable to something outside the CODEBUILD_ namespace",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-environment.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some item in flatten_list(name, "Properties.Environment.EnvironmentVariables")
	v := item.value.Name
	is_string(v)
	startswith(v, "CODEBUILD_")
}
