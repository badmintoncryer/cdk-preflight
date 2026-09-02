package cdk_preflight

import rego.v1

# The format string is opaque to every schema layer; the service requires a
# request id variable somewhere inside it.
violation contains make_diag_full("pf-apigw-access-log-format-request-id", "ERROR", name,
	"Properties.AccessLogSetting.Format",
	"Access log format has no request id variable; the stage create fails with \"Access Log format must include either $context.requestId or $context.extendedRequestId\"",
	"Add $context.requestId (or $context.extendedRequestId) to the access log format",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	fmt := resolve(name, "Properties.AccessLogSetting.Format")
	is_string(fmt)
	not contains(fmt, "$context.requestId")
	not contains(fmt, "$context.extendedRequestId")
}
