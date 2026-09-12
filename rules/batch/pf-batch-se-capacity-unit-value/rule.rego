package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-se-capacity-unit-value", "ERROR", name,
	"Properties.CapacityLimits",
	sprintf("%v is not a capacity unit (\"... is unknown capacity unit\")", [u]),
	"Use NUM_INSTANCES or an ml.* instance type as the capacity unit",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CapacityLimit.html") if {
	some name in resources_of_type("AWS::Batch::ServiceEnvironment")
	some e in flatten_list(name, "Properties.CapacityLimits")
	u := _pf_batch_oget(e.value, "CapacityUnit")
	_pf_batch_lit(u)
	u != "NUM_INSTANCES"
	not startswith(u, "ml.")
}
