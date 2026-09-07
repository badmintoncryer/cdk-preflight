package cdk_preflight

import rego.v1

# A target's dead-letter queue must be a standard SQS queue in the rule's own
# Region. Measured 2026-09-07, events:PutTargets, us-east-1: an SNS or Lambda
# ARN gives "<service> is not supported as a dead letter resource", a .fifo
# queue gives "SQS FIFO is not supported by Dead Letter Queues", and a queue
# in another Region is refused even with an identical queue policy that the
# same-Region queue is accepted with.
_pf_evtdlq_url := "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html"

_pf_evtdlq_arn(t) := a if {
	dlc := object.get(t, "DeadLetterConfig", null)
	is_object(dlc)
	a := object.get(dlc, "Arn", null)
	is_string(a)
}

_pf_evtdlq_part(arn, i) := parts[i] if {
	parts := split(arn, ":")
	count(parts) > 3
}

violation contains make_diag_full("pf-events-target-dlq", "ERROR", name,
	sprintf("Properties.Targets.%d.DeadLetterConfig.Arn", [t.index]),
	sprintf("A dead-letter queue must be an SQS queue, but '%s' is a %s resource; PutTargets fails with \"%s is not supported as a dead letter resource\"", [arn, svc, svc]),
	"Point DeadLetterConfig.Arn at an SQS queue",
	_pf_evtdlq_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	arn := _pf_evtdlq_arn(t.value)
	svc := _pf_evtdlq_part(arn, 2)
	svc != "sqs"
}

violation contains make_diag_full("pf-events-target-dlq", "ERROR", name,
	sprintf("Properties.Targets.%d.DeadLetterConfig.Arn", [t.index]),
	sprintf("'%s' is a FIFO queue; PutTargets fails with \"SQS FIFO is not supported by Dead Letter Queues\"", [arn]),
	"Use a standard queue as the dead-letter queue",
	_pf_evtdlq_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	arn := _pf_evtdlq_arn(t.value)
	_pf_evtdlq_part(arn, 2) == "sqs"
	endswith(arn, ".fifo")
}

violation contains make_diag_full("pf-events-target-dlq", "ERROR", name,
	sprintf("Properties.Targets.%d.DeadLetterConfig.Arn", [t.index]),
	sprintf("The dead-letter queue is in '%s' but the rule deploys to '%s'; EventBridge refuses a cross-Region dead-letter queue", [qr, region]),
	"Use a dead-letter queue in the rule's own Region",
	_pf_evtdlq_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	region := data.cdk_preflight.deploy_region
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	arn := _pf_evtdlq_arn(t.value)
	_pf_evtdlq_part(arn, 2) == "sqs"
	qr := _pf_evtdlq_part(arn, 3)
	qr != ""
	qr != region
}
