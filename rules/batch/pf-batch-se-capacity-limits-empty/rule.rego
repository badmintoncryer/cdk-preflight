package cdk_preflight

import rego.v1

# True absence is schema territory; only the present-and-empty list is claimed.
violation contains make_diag_full("pf-batch-se-capacity-limits-empty", "ERROR", name,
	"Properties.CapacityLimits",
	"CapacityLimits is empty (\"Capacitylimits are required.\")",
	"Declare at least one capacity limit",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-quota-shares.html") if {
	some name in resources_of_type("AWS::Batch::ServiceEnvironment")
	ls := object.get(_pf_batch_props(name), "CapacityLimits", "__pf_absent")
	is_array(ls)
	count(ls) == 0
}
