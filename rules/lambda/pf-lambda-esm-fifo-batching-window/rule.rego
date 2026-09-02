package cdk_preflight

import rego.v1

# FIFO ordering forbids holding a batch open. FIFO-ness comes from the
# queue sibling's FifoQueue flag or the .fifo arn suffix.
_pf_lfbw_is_fifo(name) if {
	q := resolve(name, "Properties.EventSourceArn")
	q in resources_of_type("AWS::SQS::Queue")
	coerce_to_bool(resolve(q, "Properties.FifoQueue")) == true
}

_pf_lfbw_is_fifo(name) if {
	arn := resolve(name, "Properties.EventSourceArn")
	is_string(arn)
	startswith(arn, "arn:")
	endswith(arn, ".fifo")
}

violation contains make_diag_full("pf-lambda-esm-fifo-batching-window", "ERROR", name,
	"Properties.MaximumBatchingWindowInSeconds",
	"Batching window on a FIFO queue source; the mapping create fails with \"Invalid request provided: Batching window is not supported for FIFO queues\"",
	"Drop MaximumBatchingWindowInSeconds, or use a standard queue",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html") if {
	some name in resources_of_type("AWS::Lambda::EventSourceMapping")
	_pf_lfbw_is_fifo(name)
	to_number(resolve(name, "Properties.MaximumBatchingWindowInSeconds")) > 0
}
