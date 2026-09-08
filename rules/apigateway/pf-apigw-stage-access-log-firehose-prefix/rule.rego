package cdk_preflight

import rego.v1

# The stream name inside the ARN carries the constraint.
violation contains make_diag_full("pf-apigw-stage-access-log-firehose-prefix", "ERROR", name,
	"Properties.AccessLogSetting.DestinationArn",
	sprintf("Access log delivery stream '%s' does not start with \"amazon-apigateway-\"; the stage create fails with \"Kinesis Firehose delivery stream name must begin with the characters 'amazon-apigateway-'\"", [stream]),
	"Rename the delivery stream to amazon-apigateway-<name>",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	arn := resolve(name, "Properties.AccessLogSetting.DestinationArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "firehose"
	startswith(parts[5], "deliverystream/")
	stream := substring(parts[5], 15, -1)
	not startswith(stream, "amazon-apigateway-")
}
