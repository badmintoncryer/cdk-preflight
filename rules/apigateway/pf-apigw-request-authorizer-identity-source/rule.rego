package cdk_preflight

import rego.v1

# REQUEST authorizers take a comma-separated list of mapping expressions; the
# TOKEN case is pf-apigw-token-authorizer-identity-source.
_pf_apgrais_ok(s) if regex.match(`^(method\.request\.(header|querystring|path)\.[^ ]+|context\.[^ ]+|stageVariables\.[^ ]+)$`, s)

violation contains make_diag_full("pf-apigw-request-authorizer-identity-source", "ERROR", name,
	"Properties.IdentitySource",
	sprintf("IdentitySource part '%s' is not a mapping expression; the authorizer create fails with \"Invalid request identity source expression: %s\"", [part, part]),
	"Use method.request.header.<name> (comma-separated for several), context.<name> or stageVariables.<name>",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGateway::Authorizer")
	resolve(name, "Properties.Type") == "REQUEST"
	src := resolve(name, "Properties.IdentitySource")
	is_string(src)
	some raw in split(src, ",")
	part := trim_space(raw)
	part != ""
	not _pf_apgrais_ok(part)
}
