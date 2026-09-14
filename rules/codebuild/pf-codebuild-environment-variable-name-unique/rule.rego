package cdk_preflight

import rego.v1

# Two entries carrying the same Name, found by index so that no count() is
# involved: the duplicate is a pairing, not a threshold.
violation contains make_diag_full("pf-codebuild-environment-variable-name-unique", "ERROR", name,
	"Properties.Environment.EnvironmentVariables",
	sprintf("Environment variable %s is declared more than once; CreateProject fails with \"EnvironmentVariable name cannot be duplicated\"", [v]),
	"Give each environment variable its own name, or keep only one entry",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-environment.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	vars := flatten_list(name, "Properties.Environment.EnvironmentVariables")
	some a in vars
	some b in vars
	a.index < b.index
	v := a.value.Name
	is_string(v)
	b.value.Name == v
}
