package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-gateway-response-status-code", "ERROR", name,
	"Properties.StatusCode",
	sprintf("StatusCode '%s' is not a three-digit HTTP status; the gateway response put fails with \"Value '%s' at 'putGatewayResponseInput.statusCode' failed to satisfy constraint\"", [c, c]),
	"Use a three-digit status code between 100 and 599",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-gatewayresponse.html") if {
	some name in resources_of_type("AWS::ApiGateway::GatewayResponse")
	c := resolve(name, "Properties.StatusCode")
	is_string(c)
	not input.resources[c]
	not regex.match(`^[1-5][0-9][0-9]$`, c)
}
