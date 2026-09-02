package cdk_preflight

import rego.v1

# The service segment lives inside the ARN string, invisible to any
# schema layer.
violation contains make_diag_full("pf-lambda-dlq-service", "ERROR", name,
	"Properties.DeadLetterConfig.TargetArn",
	sprintf("Dead letter target service '%s' is not sqs or sns; the function create fails with \"Invalid dead letter queue ARN: The service specified by the TargetArn is not supported for dead letter configuration.\"", [parts[2]]),
	"Point DeadLetterConfig at an SQS queue or SNS topic ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-deadletterconfig.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	arn := resolve(name, "Properties.DeadLetterConfig.TargetArn")
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	not parts[2] in {"sqs", "sns"}
}
