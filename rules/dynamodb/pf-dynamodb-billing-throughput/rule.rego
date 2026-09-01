package cdk_preflight

import rego.v1

_pf_ddbbt_url := "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html"

_pf_ddbbt_has_pt(name) if is_object(resolve(name, "Properties.ProvisionedThroughput"))

_pf_ddbbt_billing_present(name) if resolve(name, "Properties.BillingMode")

# BillingMode がリテラル "PROVISIONED"、または未指定（デフォルト PROVISIONED）。
# トークン値（Ref 等）は判定に使わない（誤検知防止）。
_pf_ddbbt_provisioned(name) if resolve(name, "Properties.BillingMode") == "PROVISIONED"

_pf_ddbbt_provisioned(name) if not _pf_ddbbt_billing_present(name)

violation contains make_diag_full("pf-dynamodb-billing-throughput", "ERROR", name,
	"Properties.ProvisionedThroughput",
	"ProvisionedThroughput cannot be specified when BillingMode is PAY_PER_REQUEST; CreateTable fails at deploy time",
	"Remove ProvisionedThroughput, or switch BillingMode to PROVISIONED",
	_pf_ddbbt_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	resolve(name, "Properties.BillingMode") == "PAY_PER_REQUEST"
	_pf_ddbbt_has_pt(name)
}

violation contains make_diag_full("pf-dynamodb-billing-throughput", "ERROR", name,
	"Properties.ProvisionedThroughput",
	"BillingMode is PROVISIONED (the default) but ProvisionedThroughput is missing; CreateTable fails at deploy time",
	"Add ProvisionedThroughput (ReadCapacityUnits / WriteCapacityUnits), or set BillingMode to PAY_PER_REQUEST",
	_pf_ddbbt_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	_pf_ddbbt_provisioned(name)
	not _pf_ddbbt_has_pt(name)
}
