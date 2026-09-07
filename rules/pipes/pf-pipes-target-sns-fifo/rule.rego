package cdk_preflight

import rego.v1

# "SNS FIFO topics are not supported as a pipe target." A standard topic is
# accepted. Measured 2026-09-07, pipes:CreatePipe, us-east-1.
violation contains make_diag_full("pf-pipes-target-sns-fifo", "ERROR", name,
	"Properties.Target",
	sprintf("'%s' is a FIFO topic; CreatePipe rejects it because SNS FIFO is not supported as a pipe target", [arn]),
	"Use a standard SNS topic, or send to a FIFO SQS queue instead",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-target.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	arn := resolve(name, "Properties.Target")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 2
	parts[2] == "sns"
	endswith(arn, ".fifo")
}
