package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-consumable-resource-list-max", "ERROR", name,
	"Properties.ConsumableResourceProperties.ConsumableResourceList",
	sprintf("the job declares %v consumable resources (\"Each ConsumableResourceProperty can have at most 5 consumableResources\")", [n]),
	"Declare at most 5 consumable resources",
	"https://docs.aws.amazon.com/batch/latest/userguide/resource-aware-scheduling-how-to-for-jobs.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := count(flatten_list(name, "Properties.ConsumableResourceProperties.ConsumableResourceList"))
	n > 5
}
