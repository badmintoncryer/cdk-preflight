package cdk_preflight

import rego.v1

_pf_ddbgbt_url := "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html"

# GSI-level counterpart of pf-dynamodb-billing-throughput (which covers the
# table-level pair only). Same token safety: literal BillingMode or absent
# (default PROVISIONED); token values never judged.
_pf_ddbgbt_billing_present(name) if resolve(name, "Properties.BillingMode")

_pf_ddbgbt_provisioned(name) if resolve(name, "Properties.BillingMode") == "PROVISIONED"

_pf_ddbgbt_provisioned(name) if not _pf_ddbgbt_billing_present(name)

violation contains make_diag_full("pf-dynamodb-gsi-billing-throughput", "ERROR", name,
	sprintf("Properties.GlobalSecondaryIndexes.%d.ProvisionedThroughput", [g.index]),
	sprintf("GSI '%s' specifies ProvisionedThroughput but BillingMode is PAY_PER_REQUEST; CreateTable fails with \"Property ProvisionedThroughput can't be used with PAY_PER_REQUEST BillingMode\"", [iname]),
	"Remove the GSI's ProvisionedThroughput, or switch the table to PROVISIONED",
	_pf_ddbgbt_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	resolve(name, "Properties.BillingMode") == "PAY_PER_REQUEST"
	some g in flatten_list(name, "Properties.GlobalSecondaryIndexes")
	is_object(object.get(g.value, "ProvisionedThroughput", null))
	iname := object.get(g.value, "IndexName", "<unnamed>")
}

violation contains make_diag_full("pf-dynamodb-gsi-billing-throughput", "ERROR", name,
	sprintf("Properties.GlobalSecondaryIndexes.%d.ProvisionedThroughput", [g.index]),
	sprintf("GSI '%s' is missing ProvisionedThroughput while the table bills PROVISIONED (the default); CreateTable fails with \"Property ProvisionedThroughput cannot be empty\"", [iname]),
	"Add ProvisionedThroughput to the GSI, or set BillingMode to PAY_PER_REQUEST",
	_pf_ddbgbt_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	_pf_ddbgbt_provisioned(name)
	some g in flatten_list(name, "Properties.GlobalSecondaryIndexes")
	not is_object(object.get(g.value, "ProvisionedThroughput", null))
	iname := object.get(g.value, "IndexName", "<unnamed>")
}
