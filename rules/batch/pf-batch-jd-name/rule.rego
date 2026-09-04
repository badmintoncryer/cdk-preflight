package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-name", "ERROR", name,
	"Properties.JobDefinitionName",
	sprintf("JobDefinitionName '%s' is rejected by the service: letters, numbers, hyphen and underscore, at most 128 characters", [v]),
	"Rename it to satisfy letters, numbers, hyphen and underscore, at most 128 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	v := resolve(name, "Properties.JobDefinitionName")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,128}$`, v)
}
