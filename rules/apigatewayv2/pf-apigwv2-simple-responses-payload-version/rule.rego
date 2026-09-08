package cdk_preflight

import rego.v1

_pf_agvsrpv_v2(name) if resolve(name, "Properties.AuthorizerPayloadFormatVersion") == "2.0"

violation contains make_diag_full("pf-apigwv2-simple-responses-payload-version", "ERROR", name,
	"Properties.EnableSimpleResponses",
	"EnableSimpleResponses is set but AuthorizerPayloadFormatVersion is not \"2.0\"; the authorizer create fails with \"EnableSimpleResponses can only be set for AuthorizerPayloadFormatVersion \\\"2.0\\\".\"",
	"Set AuthorizerPayloadFormatVersion: \"2.0\", or drop EnableSimpleResponses",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	resolve(name, "Properties.EnableSimpleResponses") == true
	not _pf_agvsrpv_v2(name)
}
