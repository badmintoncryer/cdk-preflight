package cdk_preflight

import rego.v1

# Streaming, Python shell and Ray jobs all reject FLEX.
violation contains make_diag_full("pf-glue-job-flex-command-name", "ERROR", name,
	"Properties.ExecutionClass",
	sprintf("ExecutionClass FLEX on a %v job; flexible execution is supported for glueetl jobs only", [cmd]),
	"Use ExecutionClass STANDARD, or change Command.Name to glueetl",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	_pf_gluelib_str(name, "Properties.ExecutionClass") == "FLEX"
	cmd := _pf_gluelib_command_name(name)
	cmd != "glueetl"
}
