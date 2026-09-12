package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-se-capacity-unit-mix", "ERROR", name,
	"Properties.CapacityLimits",
	sprintf("NUM_INSTANCES is mixed with the instance type %v (\"Capacity units must specify either number of instances OR instance type\")", [other]),
	"Express every capacity limit either as NUM_INSTANCES or as instance types",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-quota-management-resources.html") if {
	some name in resources_of_type("AWS::Batch::ServiceEnvironment")
	es := flatten_list(name, "Properties.CapacityLimits")
	units := {u | some x in es; u := object.get(x.value, "CapacityUnit", null); is_string(u)}
	"NUM_INSTANCES" in units
	others := [u | some u in units; u != "NUM_INSTANCES"]
	count(others) > 0
	other := others[0]
}
