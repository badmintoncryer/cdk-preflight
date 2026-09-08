package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-model-name-alphanumeric", "ERROR", name,
	"Properties.Name",
	sprintf("Model name '%s' is not alphanumeric; the model create fails with \"Model name must be alphanumeric: %s\"", [n, n]),
	"Use only letters and digits in the model name (no dashes or underscores)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-model.html") if {
	some name in resources_of_type("AWS::ApiGateway::Model")
	n := resolve(name, "Properties.Name")
	is_string(n)
	not input.resources[n]
	not regex.match(`^[a-zA-Z0-9]+$`, n)
}
