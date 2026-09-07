package cdk_preflight

import rego.v1

# "Invalid pipe enrichment." — only Lambda, Step Functions, API Gateway and
# an EventBridge API destination can enrich. Measured 2026-09-07 against
# pipes:CreatePipe in us-east-1: lambda, states, execute-api and events are
# accepted; sqs and sns are refused.
_pf_pipeenr_allowed := {"lambda", "states", "execute-api", "events"}

violation contains make_diag_full("pf-pipes-enrichment-type", "ERROR", name,
	"Properties.Enrichment",
	sprintf("'%s' is a %s resource; a pipe enrichment must be a Lambda function, a Step Functions state machine, an API Gateway route or an API destination, and CreatePipe fails with \"Invalid pipe enrichment.\"", [arn, svc]),
	"Point Enrichment at a Lambda function, state machine, API Gateway route or API destination",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/pipes-enrichment.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	arn := resolve(name, "Properties.Enrichment")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 2
	svc := parts[2]
	not svc in _pf_pipeenr_allowed
}
