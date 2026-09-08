package cdk_preflight

import rego.v1

_pf_ddbotb_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-ondemandthroughput.html"

# BillingMode defaults to PROVISIONED when omitted, so an absent BillingMode
# is treated the same way (mirrors pf-dynamodb-billing-throughput). Token
# values (Ref etc.) are never judged.
_pf_ddbotb_provisioned(name) if resolve(name, "Properties.BillingMode") == "PROVISIONED"

_pf_ddbotb_provisioned(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "BillingMode", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-dynamodb-ondemand-throughput-billing", "ERROR", name,
	"Properties.OnDemandThroughput",
	"OnDemandThroughput is set on a PROVISIONED table; the deploy fails with \"Property MaxReadRequestUnits for OnDemandThroughput can't be used with PROVISIONED BillingMode\"",
	"Drop OnDemandThroughput, or switch BillingMode to PAY_PER_REQUEST and drop ProvisionedThroughput instead",
	_pf_ddbotb_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	_pf_ddbotb_provisioned(name)
	is_object(resolve(name, "Properties.OnDemandThroughput"))
}

violation contains make_diag_full("pf-dynamodb-ondemand-throughput-billing", "ERROR", name,
	sprintf("Properties.GlobalSecondaryIndexes.%d.OnDemandThroughput", [g.index]),
	sprintf("GSI '%s' sets OnDemandThroughput on a PROVISIONED table; an index follows the table's billing mode and CreateTable rejects the request", [iname]),
	"Give the index ProvisionedThroughput instead, or move the whole table to PAY_PER_REQUEST",
	_pf_ddbotb_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	_pf_ddbotb_provisioned(name)
	some g in flatten_list(name, "Properties.GlobalSecondaryIndexes")
	is_object(object.get(g.value, "OnDemandThroughput", null))
	iname := object.get(g.value, "IndexName", "<unnamed>")
}
