package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ds-none-forbids-config", "ERROR", name,
	"Properties.Type",
	sprintf("Type is NONE but %s is also set; the data source create fails with \"Configs were given for data source of type None, no config is expected.\"", [cfg]),
	"Drop the configuration block, or set the Type it belongs to",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	resolve(name, "Properties.Type") == "NONE"
	some cfg in {"DynamoDBConfig", "LambdaConfig", "HttpConfig", "RelationalDatabaseConfig", "EventBridgeConfig", "OpenSearchServiceConfig"}
	is_object(resolve(name, sprintf("Properties.%s", [cfg])))
}
