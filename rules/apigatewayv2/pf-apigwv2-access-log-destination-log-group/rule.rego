package cdk_preflight

import rego.v1

# REST stages also take a Firehose stream; HTTP and WebSocket stages do not.
violation contains make_diag_full("pf-apigwv2-access-log-destination-log-group", "ERROR", name,
	"Properties.AccessLogSettings.DestinationArn",
	sprintf("Access log DestinationArn points at %s; an ApiGatewayV2 stage only takes a CloudWatch Logs log group", [parts[2]]),
	"Use a CloudWatch Logs log group ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-stage-accesslogsettings.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Stage")
	arn := resolve(name, "Properties.AccessLogSettings.DestinationArn")
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] != "logs"
}
