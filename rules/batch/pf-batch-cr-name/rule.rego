package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-cr-name", "ERROR", name,
	"Properties.ConsumableResourceName",
	sprintf("ConsumableResourceName %v is rejected by the service: letters, numbers, hyphen and underscore, at most 128 characters (\"ConsumableResource name should match a valid pattern.\")", [v]),
	"Rename the consumable resource to satisfy letters, numbers, hyphen and underscore, at most 128 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateConsumableResource.html") if {
	some name in resources_of_type("AWS::Batch::ConsumableResource")
	v := resolve(name, "Properties.ConsumableResourceName")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,128}$`, v)
}
