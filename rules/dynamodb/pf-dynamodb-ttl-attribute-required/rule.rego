package cdk_preflight

import rego.v1

# AttributeName is optional in the CFN schema (it may be omitted when
# disabling TTL) but UpdateTimeToLive requires it whenever Enabled is true.
violation contains make_diag_full("pf-dynamodb-ttl-attribute-required", "ERROR", name,
	"Properties.TimeToLiveSpecification.AttributeName",
	"TimeToLiveSpecification enables TTL without an AttributeName; UpdateTimeToLive fails with \"Missing required parameter in TimeToLiveSpecification: AttributeName\"",
	"Name the timestamp attribute the table expires on (it must not be declared in AttributeDefinitions)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-timetolivespecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	ttl := resolve(name, "Properties.TimeToLiveSpecification")
	is_object(ttl)
	object.get(ttl, "Enabled", null) == true
	object.get(ttl, "AttributeName", "__pf_absent") == "__pf_absent"
}
