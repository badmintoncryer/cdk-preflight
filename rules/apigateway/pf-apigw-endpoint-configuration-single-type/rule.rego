package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-endpoint-configuration-single-type", "ERROR", name,
	"Properties.EndpointConfiguration.Types",
	sprintf("EndpointConfiguration.Types lists %d endpoint types; the API create fails with \"Cannot create a RestApi with multiple Endpoint Types.\"", [count(types)]),
	"List exactly one of EDGE, REGIONAL or PRIVATE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-restapi-endpointconfiguration.html") if {
	some name in resources_of_type("AWS::ApiGateway::RestApi")
	types := flatten_list(name, "Properties.EndpointConfiguration.Types")
	count(types) > 1
}
