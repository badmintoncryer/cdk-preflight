package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-route-target-format", "ERROR", name,
	"Properties.Target",
	sprintf("Route Target '%s' is not an integration reference; the route create fails with \"Unexpected or malformed target in route. Correct format should be integrations/<integration_id>.\"", [t]),
	"Use \"integrations/<integration id>\" (in CDK/CloudFormation: Fn::Join over the Integration's Ref)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-route.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Route")
	t := resolve(name, "Properties.Target")
	is_string(t)
	not input.resources[t]
	not startswith(t, "integrations/")
}
