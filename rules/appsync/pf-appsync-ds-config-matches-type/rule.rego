package cdk_preflight

import rego.v1

_pf_dsconfigmatchestype_cfg := {
	"AMAZON_DYNAMODB": "DynamoDBConfig",
	"AWS_LAMBDA": "LambdaConfig",
	"HTTP": "HttpConfig",
	"RELATIONAL_DATABASE": "RelationalDatabaseConfig",
	"AMAZON_EVENTBRIDGE": "EventBridgeConfig",
	"AMAZON_OPENSEARCH_SERVICE": "OpenSearchServiceConfig",
}

violation contains make_diag_full("pf-appsync-ds-config-matches-type", "ERROR", name,
	"Properties.Type",
	sprintf("Type is %s but %s is set as well; the data source create fails with \"Multiple configs given for data source of type\"", [t, cfg]),
	"Keep only the configuration block that matches Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	t := resolve(name, "Properties.Type")
	some cfg in {"DynamoDBConfig", "LambdaConfig", "HttpConfig", "RelationalDatabaseConfig", "EventBridgeConfig", "OpenSearchServiceConfig"}
	cfg != _pf_dsconfigmatchestype_cfg[t]
	is_object(resolve(name, sprintf("Properties.%s", [cfg])))
}
