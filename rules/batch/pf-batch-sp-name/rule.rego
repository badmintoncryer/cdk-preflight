package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-sp-name", "ERROR", name,
	"Properties.Name",
	sprintf("the scheduling policy name %v is rejected by the service: letters, numbers, hyphen and underscore, at most 128 characters (\"Scheduling policy name should match a valid pattern.\")", [v]),
	"Rename the scheduling policy to satisfy letters, numbers, hyphen and underscore, at most 128 characters",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-scheduling-policy.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	v := resolve(name, "Properties.Name")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,128}$`, v)
}
