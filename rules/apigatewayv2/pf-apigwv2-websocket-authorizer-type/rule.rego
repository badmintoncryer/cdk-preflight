package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-websocket-authorizer-type", "ERROR", name,
	"Properties.AuthorizerType",
	sprintf("AuthorizerType is %s on a WebSocket API; the authorizer create fails with \"Only REQUEST authorizer type is supported on WEBSOCKET protocol Apis.\"", [t]),
	"Use AuthorizerType: REQUEST (a Lambda authorizer) on WebSocket APIs",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	_pf_apigwv2lib_protocol(name) == "WEBSOCKET"
	t := resolve(name, "Properties.AuthorizerType")
	is_string(t)
	t != "REQUEST"
}
