package cdk_preflight

import rego.v1

_pf_sqsfo_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html"

_pf_sqsfo_fix := "Set FifoQueue: true (and name the queue *.fifo) or drop the FIFO-only attributes"

_pf_sqsfo_fifo(q) if resolve(q, "Properties.FifoQueue") in {true, "true"}

# Standard queue: FifoQueue absent or literally false (an unresolvable value is neither).
_pf_sqsfo_std(q) if {
	props := input.resources[q].properties
	is_object(props)
	object.get(props, "FifoQueue", "__pf_absent") == "__pf_absent"
}

_pf_sqsfo_std(q) if resolve(q, "Properties.FifoQueue") in {false, "false"}

_pf_sqsfo_msg := {
	"ContentBasedDeduplication": "Unknown Attribute ContentBasedDeduplication.",
	"DeduplicationScope": "You can specify the DeduplicationScope only when FifoQueue is set to true.",
	"FifoThroughputLimit": "You can specify the FifoThroughputLimit only when FifoQueue is set to true.",
}

violation contains make_diag_full("pf-sqs-fifo-only-attributes", "ERROR", name,
	sprintf("Properties.%s", [attr]),
	sprintf("%s is set on a standard queue (FifoQueue is not true); CreateQueue fails with \"%s\"", [attr, _pf_sqsfo_msg[attr]]),
	_pf_sqsfo_fix, _pf_sqsfo_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	_pf_sqsfo_std(name)
	some attr, _ in _pf_sqsfo_msg
	props := input.resources[name].properties
	is_object(props)
	object.get(props, attr, "__pf_absent") != "__pf_absent"
}

_pf_sqsfo_enum contains ["DeduplicationScope", {"messageGroup", "queue"}]

_pf_sqsfo_enum contains ["FifoThroughputLimit", {"perQueue", "perMessageGroupId"}]

violation contains make_diag_full("pf-sqs-fifo-only-attributes", "ERROR", name,
	sprintf("Properties.%s", [attr]),
	sprintf("%s '%s' is not one of %v; CreateQueue fails with \"Invalid value for the parameter %s. Reason: not a supported value.\"", [attr, v, allowed, attr]),
	_pf_sqsfo_fix, _pf_sqsfo_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	some [attr, allowed] in _pf_sqsfo_enum
	v := resolve(name, sprintf("Properties.%s", [attr]))
	is_string(v)
	not v in allowed
}
