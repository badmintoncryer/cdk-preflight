package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-ce-order-duplicate-order", "ERROR", name,
	"Properties.ComputeEnvironmentOrder",
	sprintf("Order %v is used %v times (\"Duplicate ComputeEnvironment order values.\")", [o, n]),
	"Give every compute environment its own Order",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeEnvironmentOrder.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	es := flatten_list(name, "Properties.ComputeEnvironmentOrder")
	some e in es
	o := _pf_batch_oget(e.value, "Order")
	n := count([1 | some x in es; object.get(x.value, "Order", null) == o])
	n > 1
}
