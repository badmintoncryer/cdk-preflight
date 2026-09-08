package cdk_preflight

import rego.v1

# HTTP APIs take $-prefixed selection expressions; the WebSocket form
# (route.request.header.X) is a different rule.
_pf_agvhise_ok(s) if regex.match(`^\$(request\.(header|querystring)\.[^ ]+|context\.[^ ]+|stageVariables\.[^ ]+)$`, s)

violation contains make_diag_full("pf-apigwv2-http-identity-source-expression", "ERROR", name,
	"Properties.IdentitySource",
	sprintf("IdentitySource '%s' is not a selection expression; the authorizer create fails with \"Invalid identity source expression: %s\"", [s, s]),
	"Use $request.header.<name>, $request.querystring.<name>, $context.<name> or $stageVariables.<name>",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	_pf_apigwv2lib_protocol(name) == "HTTP"
	some item in flatten_list(name, "Properties.IdentitySource")
	s := item.value
	is_string(s)
	not _pf_agvhise_ok(s)
}
