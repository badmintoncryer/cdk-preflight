package cdk_preflight

import rego.v1

_pf_dsdynamodbrequiresconfig_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-ds-dynamodb-requires-config", "ERROR", name,
	"Properties.DynamoDBConfig",
	"Type is AMAZON_DYNAMODB but DynamoDBConfig is not set; the data source create has nothing to connect to",
	"Set Properties.DynamoDBConfig, or use a different Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	resolve(name, "Properties.Type") == "AMAZON_DYNAMODB"
	_pf_dsdynamodbrequiresconfig_absent(name, "DynamoDBConfig")
}
