package cdk_preflight

import rego.v1

# An event bus dead-letter queue must be SQS, the same rule the target-level
# DeadLetterConfig follows. Measured 2026-09-07, events:CreateEventBus,
# us-east-1: an SNS ARN gives "sns is not supported as a dead letter resource".
violation contains make_diag_full("pf-events-bus-dlq-arn-type", "ERROR", name,
	"Properties.DeadLetterConfig.Arn",
	sprintf("A dead-letter queue must be an SQS queue, but '%s' is a %s resource; CreateEventBus fails with \"%s is not supported as a dead letter resource\"", [arn, svc, svc]),
	"Point DeadLetterConfig.Arn at an SQS queue",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html") if {
	some name in resources_of_type("AWS::Events::EventBus")
	arn := resolve(name, "Properties.DeadLetterConfig.Arn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 2
	svc := parts[2]
	svc != "sqs"
}
