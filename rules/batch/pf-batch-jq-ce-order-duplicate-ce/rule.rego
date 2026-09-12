package cdk_preflight

import rego.v1

# A Ref/GetAtt resolves to the logical id, so two references to the same
# in-template compute environment still compare equal.
violation contains make_diag_full("pf-batch-jq-ce-order-duplicate-ce", "ERROR", name,
	"Properties.ComputeEnvironmentOrder",
	sprintf("compute environment %v is attached %v times (\"Duplicate ComputeEnvironments within order list.\")", [ce, n]),
	"List each compute environment once",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeEnvironmentOrder.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	es := flatten_list(name, "Properties.ComputeEnvironmentOrder")
	some e in es
	ce := _pf_batch_oget(e.value, "ComputeEnvironment")
	n := count([1 | some x in es; object.get(x.value, "ComputeEnvironment", null) == ce])
	n > 1
}
