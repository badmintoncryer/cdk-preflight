package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-api-key-value-length", "ERROR", name,
	"Properties.Value",
	sprintf("The API key value is %d characters; the key create fails with \"API Key value should be at least 20 characters\"", [count(v)]),
	"Use an API key value of at least 20 characters, or let API Gateway generate one",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-apikey.html") if {
	some name in resources_of_type("AWS::ApiGateway::ApiKey")
	v := resolve(name, "Properties.Value")
	is_string(v)
	not input.resources[v]
	count(v) < 20
}
