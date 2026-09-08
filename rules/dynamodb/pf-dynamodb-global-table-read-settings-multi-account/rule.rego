package cdk_preflight

import rego.v1

# Read capacity is per replica; the table-level Read*ThroughputSettings only
# exist for a multi-account global table, which is identified by
# GlobalTableSourceArn.
violation contains make_diag_full("pf-dynamodb-global-table-read-settings-multi-account", "ERROR", name,
	sprintf("Properties.%s", [prop]),
	sprintf("%s is set at the table level without GlobalTableSourceArn; read capacity belongs to each replica unless this is a multi-account global table", [prop]),
	"Move the read settings into the matching Replicas entry, or add GlobalTableSourceArn for a multi-account global table",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	props := input.resources[name].properties
	is_object(props)
	some prop in ["ReadProvisionedThroughputSettings", "ReadOnDemandThroughputSettings"]
	object.get(props, prop, "__pf_absent") != "__pf_absent"
	object.get(props, "GlobalTableSourceArn", "__pf_absent") == "__pf_absent"
}
