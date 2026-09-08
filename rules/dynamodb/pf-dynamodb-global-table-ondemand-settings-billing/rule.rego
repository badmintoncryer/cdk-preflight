package cdk_preflight

import rego.v1

# The *OnDemandThroughputSettings properties cap on-demand request units, so
# they are meaningless — and rejected — under PROVISIONED billing. The
# table-level Write settings and the per-replica Read settings are checked;
# the index-level variants were not measured.
_pf_ddbgob_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html"

_pf_ddbgob_provisioned(name) if resolve(name, "Properties.BillingMode") == "PROVISIONED"

_pf_ddbgob_provisioned(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "BillingMode", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-dynamodb-global-table-ondemand-settings-billing", "ERROR", name,
	"Properties.WriteOnDemandThroughputSettings",
	"WriteOnDemandThroughputSettings is set on a PROVISIONED global table; on-demand maximums only apply to PAY_PER_REQUEST",
	"Remove WriteOnDemandThroughputSettings, or switch BillingMode to PAY_PER_REQUEST",
	_pf_ddbgob_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddbgob_provisioned(name)
	is_object(resolve(name, "Properties.WriteOnDemandThroughputSettings"))
}

violation contains make_diag_full("pf-dynamodb-global-table-ondemand-settings-billing", "ERROR", name,
	sprintf("Properties.Replicas.%d.ReadOnDemandThroughputSettings", [r.index]),
	sprintf("Replica '%s' sets ReadOnDemandThroughputSettings while the global table is PROVISIONED; replicas follow the table's billing mode", [region]),
	"Give the replica ReadProvisionedThroughputSettings instead, or switch the table to PAY_PER_REQUEST",
	_pf_ddbgob_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddbgob_provisioned(name)
	some r in flatten_list(name, "Properties.Replicas")
	is_object(object.get(r.value, "ReadOnDemandThroughputSettings", null))
	region := object.get(r.value, "Region", "<unknown>")
}
