package cdk_preflight

import rego.v1

# The REST equivalent is pf-apigw-access-log-format-request-id.
_pf_agvalfr_has_id(f) if contains(f, "$context.requestId")

_pf_agvalfr_has_id(f) if contains(f, "$context.extendedRequestId")

violation contains make_diag_full("pf-apigwv2-access-log-format-request-id", "ERROR", name,
	"Properties.AccessLogSettings.Format",
	"The access log format has neither $context.requestId nor $context.extendedRequestId; the stage create fails with \"Access Log format must include either $context.requestId or $context.extendedRequestId\"",
	"Add $context.requestId to the access log format",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-stage-accesslogsettings.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Stage")
	f := resolve(name, "Properties.AccessLogSettings.Format")
	is_string(f)
	not _pf_agvalfr_has_id(f)
}
