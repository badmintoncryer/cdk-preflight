package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-model-name-alphanumeric", "ERROR", name,
	"Properties.Name",
	sprintf("Model name '%s' is not alphanumeric; the model create fails with \"Model name must be alphanumeric: %s\"", [n, n]),
	"Use only letters and digits in the model name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-model.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Model")
	n := resolve(name, "Properties.Name")
	is_string(n)
	not input.resources[n]
	not regex.match(`^[a-zA-Z0-9]+$`, n)
}
