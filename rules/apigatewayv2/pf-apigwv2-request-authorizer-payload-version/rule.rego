package cdk_preflight

import rego.v1

# Required on HTTP APIs only - WebSocket REQUEST authorizers must NOT set
# it, so the rule fires solely when the Api sibling is provably HTTP.
# Absence is proven against the preprocessed document (see AGENTS.md).
_pf_agv2rap_http_api(name) if {
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::ApiGatewayV2::Api")
	resolve(api, "Properties.ProtocolType") == "HTTP"
}

_pf_agv2rap_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "AuthorizerPayloadFormatVersion", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-request-authorizer-payload-version", "ERROR", name,
	"Properties.AuthorizerPayloadFormatVersion",
	"REQUEST authorizer on an HTTP API has no AuthorizerPayloadFormatVersion; the authorizer create fails with \"AuthorizerPayloadFormatVersion is a required parameter for REQUEST authorizer\"",
	"Set AuthorizerPayloadFormatVersion to 1.0 or 2.0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	resolve(name, "Properties.AuthorizerType") == "REQUEST"
	_pf_agv2rap_http_api(name)
	_pf_agv2rap_missing(name)
}
