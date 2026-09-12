package cdk_preflight

import rego.v1

# NONE and unauthenticated HTTP need no role, so only the types with their own
# configuration block are judged.
_pf_dslambdarequiresservicerole_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

_pf_dslambdarequiresservicerole_cfg := {
	"AMAZON_DYNAMODB": "DynamoDBConfig",
	"AWS_LAMBDA": "LambdaConfig",
	"HTTP": "HttpConfig",
	"RELATIONAL_DATABASE": "RelationalDatabaseConfig",
	"AMAZON_EVENTBRIDGE": "EventBridgeConfig",
	"AMAZON_OPENSEARCH_SERVICE": "OpenSearchServiceConfig",
}

violation contains make_diag_full("pf-appsync-ds-lambda-requires-service-role", "ERROR", name,
	"Properties.ServiceRoleArn",
	sprintf("a %s data source is configured but ServiceRoleArn is not set; the data source create fails because AppSync has no role to call the backend with", [t]),
	"Set ServiceRoleArn to a role AppSync can assume to reach the backend",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	t := resolve(name, "Properties.Type")
	key := _pf_dslambdarequiresservicerole_cfg[t]
	not _pf_dslambdarequiresservicerole_absent(name, key)
	_pf_dslambdarequiresservicerole_absent(name, "ServiceRoleArn")
}
