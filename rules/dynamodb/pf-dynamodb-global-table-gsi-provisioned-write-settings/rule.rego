package cdk_preflight

import rego.v1

_pf_ddbggw_provisioned(name) if resolve(name, "Properties.BillingMode") == "PROVISIONED"

_pf_ddbggw_provisioned(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "BillingMode", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-dynamodb-global-table-gsi-provisioned-write-settings", "ERROR", name,
	sprintf("Properties.GlobalSecondaryIndexes.%d.WriteProvisionedThroughputSettings", [g.index]),
	sprintf("GSI '%s' has no WriteProvisionedThroughputSettings while the global table is PROVISIONED; each index carries its own write capacity", [iname]),
	"Add WriteProvisionedThroughputSettings to the index, or move the table to PAY_PER_REQUEST",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-globalsecondaryindex.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddbggw_provisioned(name)
	some g in flatten_list(name, "Properties.GlobalSecondaryIndexes")
	object.get(g.value, "WriteProvisionedThroughputSettings", "__pf_absent") == "__pf_absent"
	iname := object.get(g.value, "IndexName", "<unnamed>")
}
