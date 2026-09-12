package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-se-name", "ERROR", name,
	"Properties.ServiceEnvironmentName",
	sprintf("ServiceEnvironmentName %v is rejected by the service: letters, numbers, hyphen and underscore, at most 128 characters (\"Service environment name should match a valid pattern.\")", [v]),
	"Rename the service environment to satisfy letters, numbers, hyphen and underscore, at most 128 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateServiceEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ServiceEnvironment")
	v := resolve(name, "Properties.ServiceEnvironmentName")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,128}$`, v)
}
