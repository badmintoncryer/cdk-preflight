package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-se-capacity-limits-max", "ERROR", name,
	"Properties.CapacityLimits",
	sprintf("the service environment declares %v capacity limits (\"Number of capacity limits exceeds 5.\")", [n]),
	"Keep at most 5 capacity limits",
	"https://docs.aws.amazon.com/batch/latest/userguide/quota-shares.html") if {
	some name in resources_of_type("AWS::Batch::ServiceEnvironment")
	n := count(flatten_list(name, "Properties.CapacityLimits"))
	n > 5
}
