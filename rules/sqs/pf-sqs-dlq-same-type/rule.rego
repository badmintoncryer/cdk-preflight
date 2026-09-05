package cdk_preflight

import rego.v1

_pf_sqsdlq_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html"

_pf_sqsdlq_fix := "Point a FIFO queue at a FIFO dead-letter queue (*.fifo) and a standard queue at a standard one"

_pf_sqsdlq_fifo(q) if resolve(q, "Properties.FifoQueue") in {true, "true"}

# Standard queue: FifoQueue absent or literally false (an unresolvable value is neither).
_pf_sqsdlq_std(q) if {
	props := input.resources[q].properties
	is_object(props)
	object.get(props, "FifoQueue", "__pf_absent") == "__pf_absent"
}

_pf_sqsdlq_std(q) if resolve(q, "Properties.FifoQueue") in {false, "false"}

# RedrivePolicy arrives as a JSON object or as a JSON string (both are valid CloudFormation).
_pf_sqsdlq_pol(name) := pol if {
	pol := object.get(input.resources[name].properties, "RedrivePolicy", null)
	is_object(pol)
}

_pf_sqsdlq_pol(name) := pol if {
	raw := object.get(input.resources[name].properties, "RedrivePolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

# The engine's E3502 (CFN_LINT) already compares the types when
# deadLetterTargetArn is Fn::GetAtt of a queue in the template (verified
# against 1.7.0-beta on 2026-09-05). Only a literal ARN — an imported queue —
# escapes it, and the .fifo suffix tells the type.
_pf_sqsdlq_literal(name) := arn if {
	arn := object.get(_pf_sqsdlq_pol(name), "deadLetterTargetArn", null)
	is_string(arn)
	regex.match("^arn:[^:]+:sqs:", arn)
	not contains(arn, "${")
}

violation contains make_diag_full("pf-sqs-dlq-same-type", "ERROR", name,
	"Properties.RedrivePolicy.deadLetterTargetArn",
	sprintf("a FIFO queue points at the standard dead-letter queue '%s'; CreateQueue fails with \"Dead-letter queue must be same type of queue as the source.\"", [arn]),
	_pf_sqsdlq_fix, _pf_sqsdlq_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	_pf_sqsdlq_fifo(name)
	arn := _pf_sqsdlq_literal(name)
	not endswith(arn, ".fifo")
}

violation contains make_diag_full("pf-sqs-dlq-same-type", "ERROR", name,
	"Properties.RedrivePolicy.deadLetterTargetArn",
	sprintf("a standard queue points at the FIFO dead-letter queue '%s'; CreateQueue fails with \"Dead-letter queue must be same type of queue as the source.\"", [arn]),
	_pf_sqsdlq_fix, _pf_sqsdlq_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	_pf_sqsdlq_std(name)
	arn := _pf_sqsdlq_literal(name)
	endswith(arn, ".fifo")
}
