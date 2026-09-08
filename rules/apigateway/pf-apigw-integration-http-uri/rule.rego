package cdk_preflight

import rego.v1

_pf_apgihu_ok(uri) if startswith(uri, "http://")

_pf_apgihu_ok(uri) if startswith(uri, "https://")

violation contains make_diag_full("pf-apigw-integration-http-uri", "ERROR", name,
	"Properties.Integration.Uri",
	sprintf("Integration.Uri '%s' is not an HTTP(S) endpoint; the method create fails with \"Invalid HTTP endpoint specified for URI\"", [uri]),
	"Use a full http:// or https:// URL for an HTTP integration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	resolve(name, "Properties.Integration.Type") in {"HTTP", "HTTP_PROXY"}
	uri := resolve(name, "Properties.Integration.Uri")
	is_string(uri)
	not input.resources[uri]
	not _pf_apgihu_ok(uri)
}
