package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-se-max-capacity-min", "ERROR", name,
	"Properties.CapacityLimits",
	sprintf("a capacity limit sets MaxCapacity %v (\"Max capacity must be more than 0.\")", [n]),
	"Set MaxCapacity to 1 or more",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CapacityLimit.html") if {
	some name in resources_of_type("AWS::Batch::ServiceEnvironment")
	some e in flatten_list(name, "Properties.CapacityLimits")
	n := to_number(_pf_batch_oget(e.value, "MaxCapacity"))
	n < 1
}
