package cdk_preflight

import rego.v1

_pf_sqssfx_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html"

_pf_sqssfx_fix := "Set FifoQueue: true or drop the .fifo suffix"

_pf_sqssfx_fifo(q) if resolve(q, "Properties.FifoQueue") in {true, "true"}

# Standard queue: FifoQueue absent or literally false (an unresolvable value is neither).
_pf_sqssfx_std(q) if {
	props := input.resources[q].properties
	is_object(props)
	object.get(props, "FifoQueue", "__pf_absent") == "__pf_absent"
}

_pf_sqssfx_std(q) if resolve(q, "Properties.FifoQueue") in {false, "false"}

# The opposite direction (FifoQueue true, name without .fifo) is the engine's
# E2504 / E3501; verified against 1.7.0-beta on 2026-09-05.
violation contains make_diag_full("pf-sqs-fifo-name-suffix", "ERROR", name,
	"Properties.QueueName",
	sprintf("QueueName '%s' ends with .fifo but the queue is standard (FifoQueue is not true); CreateQueue fails with \"Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length\"", [n]),
	_pf_sqssfx_fix, _pf_sqssfx_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	n := resolve(name, "Properties.QueueName")
	is_string(n)
	endswith(n, ".fifo")
	_pf_sqssfx_std(name)
}
