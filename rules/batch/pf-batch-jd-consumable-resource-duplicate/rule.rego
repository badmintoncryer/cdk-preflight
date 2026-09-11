package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-consumable-resource-duplicate", "ERROR", name,
	"Properties.ConsumableResourceProperties.ConsumableResourceList",
	sprintf("consumable resource %v is declared %v times (\"Cannot have duplicate consumableResource in consumableResourceProperties\")", [r, n]),
	"Declare each consumable resource once",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ConsumableResourceProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	entries := flatten_list(name, "Properties.ConsumableResourceProperties.ConsumableResourceList")
	some e in entries
	r := _pf_batch_oget(e.value, "ConsumableResource")
	_pf_batch_lit(r)
	n := count([1 | some x in entries; object.get(x.value, "ConsumableResource", null) == r])
	n > 1
}
