package cdk_preflight

import rego.v1

# The 2.0 event format is Lambda-only; HTTP_PROXY backends must stay on
# 1.0. Scoped to the benched shape (Api sibling provably HTTP).
_pf_agv2hpp_http_api(name) if {
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::ApiGatewayV2::Api")
	resolve(api, "Properties.ProtocolType") == "HTTP"
}

violation contains make_diag_full("pf-apigwv2-http-proxy-payload-version", "ERROR", name,
	"Properties.PayloadFormatVersion",
	"HTTP_PROXY integrations only support PayloadFormatVersion 1.0; the integration create fails with \"PayloadFormatVersion 2.0 is not supported for integration of type HTTP_PROXY\"",
	"Set PayloadFormatVersion to 1.0 (or omit it), or switch to an AWS_PROXY integration for 2.0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	resolve(name, "Properties.IntegrationType") == "HTTP_PROXY"
	_pf_agv2hpp_http_api(name)
	resolve(name, "Properties.PayloadFormatVersion") == "2.0"
}
