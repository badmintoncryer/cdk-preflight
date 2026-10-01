package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-default-ttl-max", "ERROR", name, "Properties.DefaultTimeToLive",
	sprintf("DefaultTimeToLive is %v seconds; Keyspaces answers \"default_time_to_live must be less than or equal to 630720000\"", [v]),
	"Set DefaultTimeToLive to 630720000 or less",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-table.html#cfn-cassandra-table-defaulttimetolive") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	v := object.get(input.resources[name].properties, "DefaultTimeToLive", null)
	is_number(v)
	v > 630720000
}
