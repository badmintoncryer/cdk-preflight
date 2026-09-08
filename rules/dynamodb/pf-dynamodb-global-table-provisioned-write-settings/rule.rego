package cdk_preflight

import rego.v1

# Write capacity is shared by every replica, so it lives on the global table
# itself. BillingMode defaults to PROVISIONED when omitted.
_pf_ddbgpw_provisioned(name) if resolve(name, "Properties.BillingMode") == "PROVISIONED"

_pf_ddbgpw_provisioned(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "BillingMode", "__pf_absent") == "__pf_absent"
}

_pf_ddbgpw_has(name) if is_object(resolve(name, "Properties.WriteProvisionedThroughputSettings"))

violation contains make_diag_full("pf-dynamodb-global-table-provisioned-write-settings", "ERROR", name,
	"Properties.WriteProvisionedThroughputSettings",
	"BillingMode is PROVISIONED (the default) but WriteProvisionedThroughputSettings is missing; the global table cannot be created without write capacity",
	"Add WriteProvisionedThroughputSettings (WriteCapacityUnits or WriteCapacityAutoScalingSettings), or set BillingMode to PAY_PER_REQUEST",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddbgpw_provisioned(name)
	not _pf_ddbgpw_has(name)
}
