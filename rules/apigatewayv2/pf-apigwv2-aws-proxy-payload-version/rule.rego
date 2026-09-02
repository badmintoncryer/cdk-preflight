package cdk_preflight

import rego.v1

# Scoped to integrations whose Api sibling is provably HTTP (the benched
# shape); WebSocket integrations are out of scope.
_pf_agv2app_http_api(name) if {
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::ApiGatewayV2::Api")
	resolve(api, "Properties.ProtocolType") == "HTTP"
}

violation contains make_diag_full("pf-apigwv2-aws-proxy-payload-version", "ERROR", name,
	"Properties.PayloadFormatVersion",
	sprintf("PayloadFormatVersion '%s' does not exist; the integration create fails with \"Unsupported PayloadFormatVersion: %s\"", [pv, pv]),
	"Use 1.0 or 2.0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	resolve(name, "Properties.IntegrationType") == "AWS_PROXY"
	_pf_agv2app_http_api(name)
	pv := resolve(name, "Properties.PayloadFormatVersion")
	is_string(pv)
	not pv in {"1.0", "2.0"}
}
