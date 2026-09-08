package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-stage-access-log-destination-arn", "ERROR", name,
	"Properties.AccessLogSetting.DestinationArn",
	sprintf("Access log DestinationArn points at %s; the stage create fails with \"The ARN must be a valid CloudWatch Logs log group or Kinesis Data Firehose delivery stream\"", [parts[2]]),
	"Use a CloudWatch Logs log group ARN or a Kinesis Data Firehose delivery stream ARN",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	arn := resolve(name, "Properties.AccessLogSetting.DestinationArn")
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	not parts[2] in {"logs", "firehose"}
}
