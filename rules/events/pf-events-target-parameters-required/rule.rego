package cdk_preflight

import rego.v1

# ECS and Batch targets carry mandatory launch parameters, and a FIFO queue
# target needs a message group; PutTargets fails with "Parameter(s) <block>
# must be specified for target: <id>". Measured 2026-09-07, us-east-1.
_pf_evtpq_required := {"ecs": "EcsParameters", "batch": "BatchParameters"}

_pf_evtpq_service(arn) := parts[2] if {
	parts := split(arn, ":")
	count(parts) > 2
}

_pf_evtpq_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html"

violation contains make_diag_full("pf-events-target-parameters-required", "ERROR", name,
	sprintf("Properties.Targets.%d.%s", [t.index, block]),
	sprintf("Target '%s' is a %s target, which requires %s; PutTargets fails with \"Parameter(s) %s must be specified for target: %s\"", [tid, svc, block, block, tid]),
	sprintf("Add %s to the target", [block]),
	_pf_evtpq_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	arn := object.get(t.value, "Arn", null)
	is_string(arn)
	svc := _pf_evtpq_service(arn)
	block := _pf_evtpq_required[svc]
	object.get(t.value, block, "__pf_absent") == "__pf_absent"
	tid := object.get(t.value, "Id", "<target>")
}

violation contains make_diag_full("pf-events-target-parameters-required", "ERROR", name,
	sprintf("Properties.Targets.%d.SqsParameters", [t.index]),
	sprintf("Target '%s' is a FIFO queue, which requires SqsParameters.MessageGroupId; PutTargets fails with \"Parameter(s) SqsParameters must be specified for target: %s\"", [tid, tid]),
	"Add SqsParameters.MessageGroupId to the target",
	_pf_evtpq_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	arn := object.get(t.value, "Arn", null)
	is_string(arn)
	_pf_evtpq_service(arn) == "sqs"
	endswith(arn, ".fifo")
	object.get(t.value, "SqsParameters", "__pf_absent") == "__pf_absent"
	tid := object.get(t.value, "Id", "<target>")
}
